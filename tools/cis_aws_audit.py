#!/usr/bin/env python3
"""Read-only AWS environment audit against the CIS AWS Foundations Benchmark v7.0.0."""

import argparse
import csv
import io
import json
import sys
import time
from datetime import datetime, timezone, timedelta

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

BENCHMARK = "CIS AWS Foundations Benchmark v7.0.0"
REMOTE_ADMIN_PORTS = (22, 3389)
CIFS_PORT = 445
PW_MIN_LENGTH = 14
PW_REUSE_MIN = 24
UNUSED_DAYS = 45
KEY_ROTATION_DAYS = 90
SUPPORT_POLICY_ARN = "arn:aws:iam::aws:policy/AWSSupportAccess"
CLOUDSHELL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"

# Required substrings per monitoring control. A single CloudWatch Logs metric
# filter satisfies a control when every listed substring is present in its pattern.
MONITORING = {
    "5.1": ("Ensure unauthorized API calls are monitored",
            ["UnauthorizedOperation", "AccessDenied"]),
    "5.2": ("Ensure management console sign-in without MFA is monitored",
            ["ConsoleLogin", "MFAUsed"]),
    "5.3": ("Ensure usage of the 'root' account is monitored",
            ["userIdentity.type", "Root"]),
    "5.4": ("Ensure IAM policy changes are monitored",
            ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy",
             "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
             "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy",
             "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
             "AttachGroupPolicy", "DetachGroupPolicy"]),
    "5.5": ("Ensure CloudTrail configuration changes are monitored",
            ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"]),
    "5.6": ("Ensure AWS Management Console authentication failures are monitored",
            ["ConsoleLogin", "Failed authentication"]),
    "5.7": ("Ensure disabling or scheduled deletion of customer created CMKs is monitored",
            ["kms.amazonaws.com", "DisableKey", "ScheduleKeyDeletion"]),
    "5.8": ("Ensure S3 bucket policy changes are monitored",
            ["s3.amazonaws.com", "PutBucketAcl", "PutBucketPolicy", "PutBucketCors",
             "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy",
             "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication"]),
    "5.9": ("Ensure AWS Config configuration changes are monitored",
            ["config.amazonaws.com", "StopConfigurationRecorder", "DeleteDeliveryChannel",
             "PutDeliveryChannel", "PutConfigurationRecorder"]),
    "5.10": ("Ensure security group changes are monitored",
             ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
              "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
              "CreateSecurityGroup", "DeleteSecurityGroup", "ModifySecurityGroupRules"]),
    "5.11": ("Ensure Network Access Control List (NACL) changes are monitored",
             ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl",
              "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"]),
    "5.12": ("Ensure changes to network gateways are monitored",
             ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway",
              "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"]),
    "5.13": ("Ensure route table changes are monitored",
             ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation",
              "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"]),
    "5.14": ("Ensure VPC changes are monitored",
             ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection",
              "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection",
              "RejectVpcPeeringConnection", "AttachClassicLinkVpc", "DetachClassicLinkVpc",
              "DisableVpcClassicLink", "EnableVpcClassicLink"]),
    "5.15": ("Ensure AWS Organizations changes are monitored",
             ["organizations.amazonaws.com", "AcceptHandshake", "AttachPolicy",
              "CreateAccount", "CreateOrganizationalUnit", "CreatePolicy", "DeclineHandshake",
              "DeleteOrganization", "DeleteOrganizationalUnit", "DeletePolicy", "DetachPolicy",
              "DisablePolicyType", "EnablePolicyType", "InviteAccountToOrganization",
              "LeaveOrganization", "MoveAccount", "RemoveAccountFromOrganization", "UpdatePolicy"]),
}

MONITORING_LEVEL = {
    "5.1": 2, "5.2": 1, "5.3": 1, "5.4": 1, "5.5": 1, "5.6": 2, "5.7": 2, "5.8": 1,
    "5.9": 2, "5.10": 2, "5.11": 2, "5.12": 1, "5.13": 1, "5.14": 1, "5.15": 1,
}


def now_utc():
    return datetime.now(timezone.utc)


def parse_ts(value):
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


def days_since(dt):
    if dt is None:
        return None
    return (now_utc() - dt).days


def paginate(client, method, key, **kwargs):
    out = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


class Finding:
    def __init__(self, control_id, title, section, level, audit_type):
        self.control_id = control_id
        self.title = title
        self.section = section
        self.level = level
        self.audit_type = audit_type
        self.status = "error"
        self.scope = "account"
        self.resources = []
        self.detail = ""
        self.remediation = ""

    def to_dict(self):
        return {
            "control_id": self.control_id,
            "title": self.title,
            "section": self.section,
            "level": self.level,
            "cis_audit_type": self.audit_type,
            "status": self.status,
            "scope": self.scope,
            "affected_resources": self.resources,
            "detail": self.detail,
            "remediation": self.remediation,
        }


class Cache:
    """Session holder that memoizes clients and expensive shared reads."""

    def __init__(self, profile=None, region_filter=None):
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"})
        self._clients = {}
        self._regions = None
        self._region_filter = region_filter
        self._cred_report = None
        self._pw_policy = "unset"
        self._trail = "unset"
        self.account_id = None

    def client(self, service, region=None):
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=region, config=self.cfg)
        return self._clients[key]

    def whoami(self):
        if self.account_id is None:
            self.account_id = self.client("sts").get_caller_identity()["Account"]
        return self.account_id

    def regions(self):
        if self._regions is None:
            ec2 = self.client("ec2", self.home_region())
            data = ec2.describe_regions(AllRegions=False)["Regions"]
            names = sorted(r["RegionName"] for r in data)
            if self._region_filter:
                names = [r for r in names if r in self._region_filter]
            self._regions = names
        return self._regions

    def home_region(self):
        return self.session.region_name or "us-east-1"

    def credential_report(self):
        if self._cred_report is None:
            iam = self.client("iam")
            for _ in range(20):
                state = iam.generate_credential_report()["State"]
                if state == "COMPLETE":
                    break
                time.sleep(3)
            raw = iam.get_credential_report()["Content"].decode("utf-8")
            self._cred_report = list(csv.DictReader(io.StringIO(raw)))
        return self._cred_report

    def password_policy(self):
        if self._pw_policy == "unset":
            try:
                self._pw_policy = self.client("iam").get_account_password_policy()["PasswordPolicy"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchEntity":
                    self._pw_policy = None
                else:
                    raise
        return self._pw_policy

    def active_trail(self):
        """Resolve the multi-region, actively logging trail and its log group name."""
        if self._trail == "unset":
            self._trail = None
            ct = self.client("cloudtrail", self.home_region())
            try:
                trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            except ClientError:
                trails = []
            for t in trails:
                if not t.get("IsMultiRegionTrail"):
                    continue
                home = t.get("HomeRegion", self.home_region())
                tct = self.client("cloudtrail", home)
                try:
                    status = tct.get_trail_status(Name=t["TrailARN"])
                except ClientError:
                    continue
                if not status.get("IsLogging"):
                    continue
                group_arn = t.get("CloudWatchLogsLogGroupArn")
                group = group_arn.split(":log-group:")[1].split(":")[0] if group_arn else None
                self._trail = {"trail": t, "home": home, "log_group": group}
                break
        return self._trail


# ---------------------------------------------------------------------------
# Section 2 - IAM and account
# ---------------------------------------------------------------------------

def check_2_3(c, f):
    try:
        c.client("account").get_alternate_contact(AlternateContactType="SECURITY")
        f.status = "pass"
        f.detail = "Security alternate contact is registered."
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            f.status = "fail"
            f.detail = "No SECURITY alternate contact registered."
        else:
            raise


def check_2_4(c, f):
    root = _root_row(c)
    active = root.get("access_key_1_active") == "true" or root.get("access_key_2_active") == "true"
    f.status = "fail" if active else "pass"
    f.detail = "Root access key present." if active else "No root access key exists."


def check_2_5(c, f):
    summary = c.client("iam").get_account_summary()["SummaryMap"]
    enabled = summary.get("AccountMFAEnabled", 0) == 1
    f.status = "pass" if enabled else "fail"
    f.detail = "Root MFA enabled." if enabled else "Root MFA not enabled."


def check_2_6(c, f):
    iam = c.client("iam")
    devices = paginate(iam, "list_virtual_mfa_devices", "VirtualMFADevices", AssignmentStatus="Any")
    root_virtual = any(
        d.get("User", {}).get("Arn", "").endswith(":root") for d in devices
    )
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        f.status = "fail"
        f.detail = "Root MFA not enabled at all."
    elif root_virtual:
        f.status = "fail"
        f.detail = "Root MFA is a virtual device, not hardware."
    else:
        f.status = "pass"
        f.detail = "Root MFA present and not a virtual device."


def check_2_8(c, f):
    p = c.password_policy()
    if not p:
        f.status = "fail"
        f.detail = "No account password policy set."
        return
    length = p.get("MinimumPasswordLength", 0)
    f.status = "pass" if length >= PW_MIN_LENGTH else "fail"
    f.detail = "Minimum length is %s." % length


def check_2_9(c, f):
    p = c.password_policy()
    if not p:
        f.status = "fail"
        f.detail = "No account password policy set."
        return
    reuse = p.get("PasswordReusePrevention", 0)
    f.status = "pass" if reuse >= PW_REUSE_MIN else "fail"
    f.detail = "PasswordReusePrevention is %s." % reuse


def check_2_10(c, f):
    bad = []
    for row in c.credential_report():
        if row["user"] == "<root_account>":
            continue
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            bad.append(row["user"])
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d console users without MFA." % len(bad)


def check_2_11(c, f):
    bad = []
    for row in c.credential_report():
        if row["user"] == "<root_account>":
            continue
        if row.get("password_enabled") == "true":
            d = days_since(parse_ts(row.get("password_last_used")))
            if d is not None and d > UNUSED_DAYS:
                bad.append("%s (password %sd)" % (row["user"], d))
        for n in ("1", "2"):
            if row.get("access_key_%s_active" % n) == "true":
                used = days_since(parse_ts(row.get("access_key_%s_last_used_date" % n)))
                if used is not None and used > UNUSED_DAYS:
                    bad.append("%s (key%s %sd)" % (row["user"], n, used))
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d credentials unused beyond %d days." % (len(bad), UNUSED_DAYS)


def check_2_12(c, f):
    bad = []
    for row in c.credential_report():
        if row["user"] == "<root_account>":
            continue
        for n in ("1", "2"):
            if row.get("access_key_%s_active" % n) == "true":
                age = days_since(parse_ts(row.get("access_key_%s_last_rotated" % n)))
                if age is not None and age > KEY_ROTATION_DAYS:
                    bad.append("%s (key%s %sd)" % (row["user"], n, age))
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d active keys older than %d days." % (len(bad), KEY_ROTATION_DAYS)


def check_2_13(c, f):
    iam = c.client("iam")
    bad = []
    for u in paginate(iam, "list_users", "Users"):
        name = u["UserName"]
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        inline = iam.list_user_policies(UserName=name)["PolicyNames"]
        if attached or inline:
            bad.append(name)
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d users with directly attached permissions." % len(bad)


def check_2_14(c, f):
    iam = c.client("iam")
    bad = []
    for pol in paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True):
        doc = _policy_default_doc(iam, pol["Arn"], pol["DefaultVersionId"])
        if _is_full_admin(doc):
            bad.append(pol["Arn"])
    for pol in paginate(iam, "list_policies", "Policies", Scope="AWS", OnlyAttached=True):
        doc = _policy_default_doc(iam, pol["Arn"], pol["DefaultVersionId"])
        if _is_full_admin(doc):
            bad.append(pol["Arn"])
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d attached policies grant full *:* admin." % len(bad)


def check_2_15(c, f):
    iam = c.client("iam")
    try:
        ents = iam.list_entities_for_policy(PolicyArn=SUPPORT_POLICY_ARN)
        attached = ents["PolicyRoles"] or ents["PolicyUsers"] or ents["PolicyGroups"]
        f.status = "pass" if attached else "fail"
        f.detail = "Support role present." if attached else "AWSSupportAccess not attached to any entity."
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            f.status = "fail"
            f.detail = "AWSSupportAccess policy not found."
        else:
            raise


def check_2_16(c, f):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        for res in _reservations(ec2):
            for inst in res["Instances"]:
                if inst.get("State", {}).get("Name") in ("terminated", "stopped"):
                    continue
                if not inst.get("IamInstanceProfile"):
                    bad.append("%s/%s" % (region, inst["InstanceId"]))
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d running instances without an instance role." % len(bad)


def check_2_17(c, f):
    iam = c.client("iam")
    expired = []
    for cert in paginate(iam, "list_server_certificates", "ServerCertificateMetadataList"):
        exp = cert.get("Expiration")
        if exp and exp < now_utc():
            expired.append(cert["ServerCertificateName"])
    f.resources = expired
    f.status = "fail" if expired else "pass"
    f.detail = "%d expired IAM server certificates." % len(expired)


def check_2_18(c, f):
    missing = []
    for region in c.regions():
        aa = c.client("accessanalyzer", region)
        analyzers = paginate(aa, "list_analyzers", "analyzers", type="ACCOUNT")
        org = paginate(aa, "list_analyzers", "analyzers", type="ORGANIZATION")
        active = [a for a in analyzers + org if a.get("status") == "ACTIVE"]
        if not active:
            missing.append(region)
    f.scope = "regional"
    f.resources = missing
    f.status = "fail" if missing else "pass"
    f.detail = "%d regions without an active IAM Access Analyzer." % len(missing)


def check_2_20(c, f):
    iam = c.client("iam")
    try:
        ents = iam.list_entities_for_policy(PolicyArn=CLOUDSHELL_POLICY_ARN)
        attached = ents["PolicyRoles"] + ents["PolicyUsers"] + ents["PolicyGroups"]
        names = [e.get("RoleName") or e.get("UserName") or e.get("GroupName") for e in attached]
        f.resources = names
        f.status = "fail" if names else "pass"
        f.detail = "AWSCloudShellFullAccess attached to %d entities." % len(names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            f.status = "pass"
            f.detail = "AWSCloudShellFullAccess not present."
        else:
            raise


# ---------------------------------------------------------------------------
# Section 3 - storage
# ---------------------------------------------------------------------------

def check_3_1_1(c, f):
    s3 = c.client("s3")
    bad = []
    for b in _buckets(c):
        try:
            pol = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])
        except ClientError:
            bad.append(b)
            continue
        if not _denies_insecure_transport(pol):
            bad.append(b)
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d buckets without an HTTPS-only deny." % len(bad)


def check_3_1_4(c, f):
    account = c.whoami()
    try:
        cfg = c.client("s3control").get_public_access_block(AccountId=account)
        block = cfg["PublicAccessBlockConfiguration"]
        if all(block.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                       "BlockPublicPolicy", "RestrictPublicBuckets")):
            f.status = "pass"
            f.detail = "Account-level Block Public Access fully enabled."
            return
    except ClientError:
        pass
    s3 = c.client("s3")
    bad = []
    for b in _buckets(c):
        try:
            block = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
            if not all(block.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                              "BlockPublicPolicy", "RestrictPublicBuckets")):
                bad.append(b)
        except ClientError:
            bad.append(b)
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d buckets without full Block Public Access." % len(bad)


def check_3_1_2(c, f):
    s3 = c.client("s3")
    bad = []
    for b in _buckets(c):
        try:
            v = s3.get_bucket_versioning(Bucket=b)
            if v.get("MFADelete") != "Enabled":
                bad.append(b)
        except ClientError:
            bad.append(b)
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d buckets without MFA Delete." % len(bad)


def check_3_2_1(c, f):
    _rds_flag(c, f, lambda i: i.get("StorageEncrypted"), "without encryption at rest")


def check_3_2_2(c, f):
    _rds_flag(c, f, lambda i: i.get("AutoMinorVersionUpgrade"), "without auto minor version upgrade")


def check_3_2_3(c, f):
    _rds_flag(c, f, lambda i: not i.get("PubliclyAccessible"), "that are publicly accessible")


def check_3_2_4(c, f):
    _rds_flag(c, f, lambda i: i.get("MultiAZ"), "without Multi-AZ")


def check_3_3_1(c, f):
    bad = []
    for region in c.regions():
        efs = c.client("efs", region)
        try:
            systems = paginate(efs, "describe_file_systems", "FileSystems")
        except (ClientError, EndpointConnectionError):
            continue
        for fs in systems:
            if not fs.get("Encrypted"):
                bad.append("%s/%s" % (region, fs["FileSystemId"]))
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d EFS file systems without encryption." % len(bad)


# ---------------------------------------------------------------------------
# Section 4 - logging
# ---------------------------------------------------------------------------

def check_4_1(c, f):
    t = c.active_trail()
    if not t:
        f.status = "fail"
        f.detail = "No multi-region trail actively logging."
        return
    home = t["home"]
    tct = c.client("cloudtrail", home)
    sel = _mgmt_read_write(tct, t["trail"])
    if sel:
        f.status = "pass"
        f.detail = "Multi-region trail logging management events (%s)." % t["trail"]["Name"]
    else:
        f.status = "fail"
        f.detail = "Trail present but not logging all management events."


def check_4_2(c, f):
    t = c.active_trail()
    if not t:
        f.status = "fail"
        f.detail = "No active multi-region trail to evaluate."
        return
    f.status = "pass" if t["trail"].get("LogFileValidationEnabled") else "fail"
    f.detail = "Log file validation %s." % ("enabled" if f.status == "pass" else "disabled")


def check_4_3(c, f):
    missing = []
    for region in c.regions():
        cfg = c.client("config", region)
        try:
            recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
            status = {s["name"]: s for s in
                      cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]}
        except (ClientError, EndpointConnectionError):
            missing.append(region)
            continue
        ok = False
        for r in recorders:
            grp = r.get("recordingGroup", {})
            st = status.get(r["name"], {})
            if st.get("recording") and (grp.get("allSupported") or grp.get("includeGlobalResourceTypes")):
                ok = True
        if not ok:
            missing.append(region)
    f.scope = "regional"
    f.resources = missing
    f.status = "fail" if missing else "pass"
    f.detail = "%d regions without AWS Config recording." % len(missing)


def check_4_4(c, f):
    t = c.active_trail()
    if not t:
        f.status = "fail"
        f.detail = "No active trail to evaluate bucket logging."
        return
    bucket = t["trail"].get("S3BucketName")
    if not bucket:
        f.status = "fail"
        f.detail = "Trail has no S3 bucket."
        return
    try:
        logging = c.client("s3").get_bucket_logging(Bucket=bucket)
        enabled = "LoggingEnabled" in logging
    except ClientError:
        enabled = False
    f.resources = [bucket]
    f.status = "pass" if enabled else "fail"
    f.detail = "Server access logging %s on %s." % ("enabled" if enabled else "disabled", bucket)


def check_4_5(c, f):
    t = c.active_trail()
    if not t:
        f.status = "fail"
        f.detail = "No active trail to evaluate encryption."
        return
    f.status = "pass" if t["trail"].get("KmsKeyId") else "fail"
    f.detail = "Trail KMS encryption %s." % ("set" if f.status == "pass" else "not set")


def check_4_6(c, f):
    bad = []
    for region in c.regions():
        kms = c.client("kms", region)
        try:
            for k in paginate(kms, "list_keys", "Keys"):
                kid = k["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                except ClientError:
                    continue
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue
                if meta.get("KeyState") != "Enabled":
                    continue
                try:
                    if not kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled"):
                        bad.append("%s/%s" % (region, kid))
                except ClientError:
                    continue
        except (ClientError, EndpointConnectionError):
            continue
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d customer symmetric CMKs without rotation." % len(bad)


def check_4_7(c, f):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        try:
            vpcs = [v["VpcId"] for v in paginate(ec2, "describe_vpcs", "Vpcs")]
            flows = paginate(ec2, "describe_flow_logs", "FlowLogs")
        except (ClientError, EndpointConnectionError):
            continue
        logged = {fl.get("ResourceId") for fl in flows}
        for v in vpcs:
            if v not in logged:
                bad.append("%s/%s" % (region, v))
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d VPCs without flow logging." % len(bad)


def check_4_8(c, f):
    _s3_data_events(c, f, want_read=False)


def check_4_9(c, f):
    _s3_data_events(c, f, want_read=True)


# ---------------------------------------------------------------------------
# Section 5 - monitoring
# ---------------------------------------------------------------------------

def make_monitoring_check(control_id):
    required = MONITORING[control_id][1]

    def check(c, f):
        t = c.active_trail()
        if not t or not t.get("log_group"):
            f.status = "fail"
            f.detail = "No active multi-region trail with a CloudWatch Logs group."
            return
        home = t["home"]
        group = t["log_group"]
        logs = c.client("logs", home)
        cw = c.client("cloudwatch", home)
        sns = c.client("sns", home)
        try:
            filters = paginate(logs, "describe_metric_filters", "metricFilters",
                               logGroupName=group)
        except ClientError:
            filters = []
        match = None
        for mf in filters:
            pattern = mf.get("filterPattern", "")
            if all(tok in pattern for tok in required):
                match = mf
                break
        if not match:
            f.status = "fail"
            f.detail = "No metric filter covering the required events."
            return
        mt = match["metricTransformations"][0]
        alarms = cw.describe_alarms_for_metric(
            MetricName=mt["metricName"], Namespace=mt.get("metricNamespace", ""))["MetricAlarms"]
        alarms = [a for a in alarms if a.get("AlarmActions")]
        if not alarms:
            f.status = "fail"
            f.detail = "Metric filter present but no alarm with an action."
            return
        if not _alarm_has_subscriber(alarms, sns):
            f.status = "fail"
            f.detail = "Alarm present but no active SNS subscription."
            return
        f.status = "pass"
        f.detail = "Metric filter, alarm, and active subscription present."

    return check


def check_5_16(c, f):
    missing = []
    for region in c.regions():
        sh = c.client("securityhub", region)
        try:
            sh.describe_hub()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidAccessException", "ResourceNotFoundException"):
                missing.append(region)
        except EndpointConnectionError:
            continue
    f.scope = "regional"
    f.resources = missing
    f.status = "fail" if missing else "pass"
    f.detail = "%d regions without Security Hub enabled." % len(missing)


# ---------------------------------------------------------------------------
# Section 6 - networking
# ---------------------------------------------------------------------------

def check_6_1_1(c, f):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        try:
            if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
                bad.append(region)
        except (ClientError, EndpointConnectionError):
            continue
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d regions without default EBS encryption." % len(bad)


def check_6_1_2(c, f):
    _sg_open_ports(c, f, (CIFS_PORT,), ("0.0.0.0/0", "::/0"), "CIFS/445")


def check_6_2(c, f):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        try:
            acls = paginate(ec2, "describe_network_acls", "NetworkAcls")
        except (ClientError, EndpointConnectionError):
            continue
        for acl in acls:
            for entry in acl.get("Entries", []):
                if entry.get("Egress"):
                    continue
                if entry.get("RuleAction") != "allow":
                    continue
                if entry.get("CidrBlock") != "0.0.0.0/0":
                    continue
                if _range_hits(entry.get("PortRange"), entry.get("Protocol"), REMOTE_ADMIN_PORTS):
                    bad.append("%s/%s" % (region, acl["NetworkAclId"]))
                    break
    f.scope = "regional"
    f.resources = sorted(set(bad))
    f.status = "fail" if bad else "pass"
    f.detail = "%d NACLs allow admin ports from 0.0.0.0/0." % len(set(bad))


def check_6_3(c, f):
    _sg_open_ports(c, f, REMOTE_ADMIN_PORTS, ("0.0.0.0/0",), "admin ports from 0.0.0.0/0")


def check_6_4(c, f):
    _sg_open_ports(c, f, REMOTE_ADMIN_PORTS, ("::/0",), "admin ports from ::/0")


def check_6_5(c, f):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        try:
            groups = paginate(ec2, "describe_security_groups", "SecurityGroups",
                              Filters=[{"Name": "group-name", "Values": ["default"]}])
        except (ClientError, EndpointConnectionError):
            continue
        for g in groups:
            if g.get("IpPermissions") or g.get("IpPermissionsEgress"):
                bad.append("%s/%s" % (region, g["GroupId"]))
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d default security groups with rules." % len(bad)


def check_6_7(c, f):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        for res in _reservations(ec2):
            for inst in res["Instances"]:
                if inst.get("State", {}).get("Name") in ("terminated", "stopped"):
                    continue
                if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                    bad.append("%s/%s" % (region, inst["InstanceId"]))
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d instances not enforcing IMDSv2." % len(bad)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _root_row(c):
    for row in c.credential_report():
        if row["user"] == "<root_account>":
            return row
    return {}


def _policy_default_doc(iam, arn, version):
    try:
        pv = iam.get_policy_version(PolicyArn=arn, VersionId=version)
        return pv["PolicyVersion"]["Document"]
    except ClientError:
        return {}


def _is_full_admin(doc):
    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = s.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


def _buckets(c):
    return [b["Name"] for b in c.client("s3").list_buckets()["Buckets"]]


def _denies_insecure_transport(pol):
    stmts = pol.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Deny":
            continue
        cond = s.get("Condition", {})
        bad = cond.get("Bool", {}).get("aws:SecureTransport")
        if bad in ("false", False):
            return True
        if "NumericLessThan" in cond and "s3:TlsVersion" in cond["NumericLessThan"]:
            return True
    return False


def _reservations(ec2):
    try:
        return paginate(ec2, "describe_instances", "Reservations")
    except (ClientError, EndpointConnectionError):
        return []


def _rds_flag(c, f, predicate, label):
    bad = []
    for region in c.regions():
        rds = c.client("rds", region)
        try:
            for i in paginate(rds, "describe_db_instances", "DBInstances"):
                if not predicate(i):
                    bad.append("%s/%s" % (region, i["DBInstanceIdentifier"]))
        except (ClientError, EndpointConnectionError):
            continue
    f.scope = "regional"
    f.resources = bad
    f.status = "fail" if bad else "pass"
    f.detail = "%d RDS instances %s." % (len(bad), label)


def _mgmt_read_write(ct, trail):
    name = trail["TrailARN"]
    try:
        adv = ct.get_event_selectors(TrailName=name)
    except ClientError:
        return False
    for sel in adv.get("EventSelectors", []):
        if sel.get("ReadWriteType") in ("All", None) and sel.get("IncludeManagementEvents", True):
            return True
    for sel in adv.get("AdvancedEventSelectors", []):
        fields = {fc.get("Field"): fc for fc in sel.get("FieldSelectors", [])}
        cat = fields.get("eventCategory", {})
        if "Management" in cat.get("Equals", []):
            return True
    return False


def _s3_data_events(c, f, want_read):
    t = c.active_trail()
    if not t:
        f.status = "fail"
        f.detail = "No active trail to evaluate S3 data events."
        return
    ct = c.client("cloudtrail", t["home"])
    try:
        sel = ct.get_event_selectors(TrailName=t["trail"]["TrailARN"])
    except ClientError:
        f.status = "fail"
        f.detail = "Unable to read event selectors."
        return
    want = "ReadOnly" if want_read else "WriteOnly"
    found = False
    for s in sel.get("EventSelectors", []):
        for dr in s.get("DataResources", []):
            if dr.get("Type") == "AWS::S3::Object" and s.get("ReadWriteType") in ("All", want):
                found = True
    for s in sel.get("AdvancedEventSelectors", []):
        fields = {fc.get("Field"): fc for fc in s.get("FieldSelectors", [])}
        res = fields.get("resources.type", {})
        rw = fields.get("readOnly", {})
        if "AWS::S3::Object" in res.get("Equals", []):
            if not rw or (str(want_read).lower() in [v.lower() for v in rw.get("Equals", [])]) or not rw.get("Equals"):
                found = True
    f.status = "pass" if found else "fail"
    f.detail = "S3 object-level %s logging %s." % (
        "read" if want_read else "write", "present" if found else "absent")


def _alarm_has_subscriber(alarms, sns):
    for a in alarms:
        for action in a.get("AlarmActions", []):
            if ":sns:" not in action:
                continue
            try:
                subs = paginate(sns, "list_subscriptions_by_topic", "Subscriptions",
                                TopicArn=action)
            except ClientError:
                continue
            for s in subs:
                if s.get("SubscriptionArn") not in ("PendingConfirmation", "Deleted", None):
                    return True
    return False


def _range_hits(port_range, protocol, ports):
    if str(protocol) == "-1":
        return True
    if not port_range:
        return False
    lo = port_range.get("From")
    hi = port_range.get("To")
    if lo is None or hi is None:
        return False
    return any(lo <= p <= hi for p in ports)


def _sg_open_ports(c, f, ports, cidrs, label):
    bad = []
    for region in c.regions():
        ec2 = c.client("ec2", region)
        try:
            groups = paginate(ec2, "describe_security_groups", "SecurityGroups")
        except (ClientError, EndpointConnectionError):
            continue
        for g in groups:
            for perm in g.get("IpPermissions", []):
                if not _perm_covers(perm, ports):
                    continue
                open_cidr = False
                for r in perm.get("IpRanges", []):
                    if r.get("CidrIp") in cidrs:
                        open_cidr = True
                for r in perm.get("Ipv6Ranges", []):
                    if r.get("CidrIpv6") in cidrs:
                        open_cidr = True
                if open_cidr:
                    bad.append("%s/%s" % (region, g["GroupId"]))
                    break
    f.scope = "regional"
    f.resources = sorted(set(bad))
    f.status = "fail" if bad else "pass"
    f.detail = "%d security groups allow %s." % (len(set(bad)), label)


def _perm_covers(perm, ports):
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return True
    if proto not in ("tcp", "6"):
        return False
    lo = perm.get("FromPort")
    hi = perm.get("ToPort")
    if lo is None or hi is None:
        return False
    return any(lo <= p <= hi for p in ports)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# id: (title, section, level, cis_audit_type, check_fn_or_None, remediation)
REGISTRY = {
    "2.1.1": ("Ensure centralized root access in AWS Organizations", 2, 2, "Manual", None,
              "Enable centralized root access management in AWS Organizations."),
    "2.1.2": ("Ensure authorization guardrails for all AWS Organization accounts", 2, 2, "Manual", None,
              "Apply SCPs/RCPs enforcing your baseline guardrails across all accounts."),
    "2.1.3": ("Ensure Organizations management account is not used for workloads", 2, 2, "Manual", None,
              "Move workloads out of the management account into member accounts."),
    "2.1.4": ("Ensure Organizational Units are structured by environment and sensitivity", 2, 2, "Manual", None,
              "Structure OUs by environment and data sensitivity."),
    "2.1.5": ("Ensure delegated admin manages AWS Organizations policies", 2, 2, "Manual", None,
              "Delegate policy administration away from the management account."),
    "2.1.6": ("Ensure delegated admins manage AWS Organizations-integrated services", 2, 2, "Manual", None,
              "Use delegated administrators for Organizations-integrated services."),
    "2.2": ("Maintain current AWS account contact details", 2, 1, "Manual", None,
            "Review and update primary account contact details."),
    "2.3": ("Ensure security contact information is registered", 2, 1, "Manual", check_2_3,
            "Register a SECURITY alternate contact via the Account API."),
    "2.4": ("Ensure no 'root' user account access key exists", 2, 1, "Automated", check_2_4,
            "Delete any access keys on the root user."),
    "2.5": ("Ensure MFA is enabled for the 'root' user account", 2, 1, "Automated", check_2_5,
            "Enable MFA on the root user."),
    "2.6": ("Ensure hardware MFA is enabled for the 'root' user account", 2, 2, "Manual", check_2_6,
            "Replace virtual root MFA with a hardware MFA device."),
    "2.7": ("Eliminate use of the 'root' user for administrative and daily tasks", 2, 1, "Manual", None,
            "Use IAM roles/users for daily work; reserve root for tasks that require it."),
    "2.8": ("Ensure IAM password policy requires minimum length of 14 or greater", 2, 1, "Automated", check_2_8,
            "Set the account password policy minimum length to 14 or more."),
    "2.9": ("Ensure IAM password policy prevents password reuse", 2, 1, "Automated", check_2_9,
            "Set PasswordReusePrevention to 24."),
    "2.10": ("Ensure MFA is enabled for all IAM users that have a console password", 2, 1, "Automated", check_2_10,
             "Enable MFA for every IAM user with console access."),
    "2.11": ("Ensure credentials unused for 45 days or more are disabled", 2, 1, "Automated", check_2_11,
             "Disable passwords and access keys unused for 45 days or more."),
    "2.12": ("Ensure access keys are rotated every 90 days or less", 2, 1, "Automated", check_2_12,
             "Rotate active access keys at least every 90 days."),
    "2.13": ("Ensure IAM users receive permissions only through groups", 2, 1, "Automated", check_2_13,
             "Remove directly attached and inline user policies; assign via groups."),
    "2.14": ("Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached", 2, 1, "Automated", check_2_14,
             "Detach policies granting Action * on Resource *; scope to least privilege."),
    "2.15": ("Ensure a support role has been created to manage incidents with AWS Support", 2, 1, "Automated", check_2_15,
             "Attach AWSSupportAccess to a dedicated support role."),
    "2.16": ("Ensure IAM instance roles are used for AWS resource access from instances", 2, 2, "Automated", check_2_16,
             "Attach instance profiles to EC2 instances instead of static credentials."),
    "2.17": ("Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed", 2, 1, "Automated", check_2_17,
             "Delete expired IAM server certificates."),
    "2.18": ("Ensure that IAM External Access Analyzer is enabled for all regions", 2, 1, "Automated", check_2_18,
             "Enable an active IAM Access Analyzer in every region."),
    "2.19": ("Ensure IAM users are managed centrally via identity federation or AWS Organizations", 2, 2, "Manual", None,
             "Manage identities centrally via federation or Organizations."),
    "2.20": ("Ensure access to AWSCloudShellFullAccess is restricted", 2, 1, "Manual", check_2_20,
             "Remove AWSCloudShellFullAccess from broad principals."),
    "2.21": ("Ensure AWS resource policies do not allow unrestricted access using \"Principal\": \"*\"", 2, 1, "Manual", None,
             "Scope resource policy principals; avoid unconditional Principal *."),
    "3.1.1": ("Ensure S3 Bucket Policy is set to deny HTTP requests", 3, 2, "Automated", check_3_1_1,
              "Add a Deny statement on aws:SecureTransport false or low TlsVersion."),
    "3.1.2": ("Ensure MFA Delete is enabled on S3 buckets", 3, 2, "Manual", check_3_1_2,
              "Enable MFA Delete on versioned buckets."),
    "3.1.3": ("Ensure all data in Amazon S3 has been discovered, classified, and secured", 3, 2, "Manual", None,
              "Use Macie or equivalent to discover and classify sensitive S3 data."),
    "3.1.4": ("Ensure that S3 is configured with 'Block Public Access' enabled", 3, 1, "Automated", check_3_1_4,
              "Enable account-level Block Public Access with all four options on."),
    "3.2.1": ("Ensure that encryption-at-rest is enabled for RDS instances", 3, 1, "Automated", check_3_2_1,
              "Enable storage encryption on RDS instances."),
    "3.2.2": ("Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances", 3, 1, "Automated", check_3_2_2,
              "Enable Auto Minor Version Upgrade on RDS instances."),
    "3.2.3": ("Ensure that RDS instances are not publicly accessible", 3, 1, "Automated", check_3_2_3,
              "Set PubliclyAccessible to false on RDS instances."),
    "3.2.4": ("Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS", 3, 1, "Manual", check_3_2_4,
              "Enable Multi-AZ on production RDS instances."),
    "3.3.1": ("Ensure that encryption is enabled for EFS file systems", 3, 1, "Automated", check_3_3_1,
              "Recreate EFS file systems with encryption enabled."),
    "4.1": ("Ensure CloudTrail is enabled in all regions", 4, 1, "Manual", check_4_1,
            "Create a multi-region trail logging all management events."),
    "4.2": ("Ensure CloudTrail log file validation is enabled", 4, 2, "Automated", check_4_2,
            "Enable log file validation on the trail."),
    "4.3": ("Ensure AWS Config is enabled in all regions", 4, 2, "Automated", check_4_3,
            "Enable AWS Config recording all supported resources in every region."),
    "4.4": ("Ensure that server access logging is enabled on the CloudTrail S3 bucket", 4, 1, "Manual", check_4_4,
            "Enable S3 server access logging on the CloudTrail bucket."),
    "4.5": ("Ensure CloudTrail logs are encrypted at rest using KMS CMKs", 4, 2, "Automated", check_4_5,
            "Configure the trail to use a KMS CMK."),
    "4.6": ("Ensure rotation for customer-created symmetric CMKs is enabled", 4, 2, "Automated", check_4_6,
            "Enable annual rotation on customer symmetric CMKs."),
    "4.7": ("Ensure VPC flow logging is enabled in all VPCs", 4, 2, "Automated", check_4_7,
            "Enable flow logs on every VPC."),
    "4.8": ("Ensure that object-level logging for write events is enabled for S3 buckets", 4, 2, "Automated", check_4_8,
            "Enable S3 object-level write data event logging on a trail."),
    "4.9": ("Ensure that object-level logging for read events is enabled for S3 buckets", 4, 2, "Automated", check_4_9,
            "Enable S3 object-level read data event logging on a trail."),
    "4.10": ("Ensure all AWS-managed web front-end services have access logging enabled", 4, 1, "Manual", None,
             "Enable access logging on ELB, CloudFront, API Gateway, and WAF."),
    "5.16": ("Ensure AWS Security Hub is enabled", 5, 2, "Automated", check_5_16,
             "Enable Security Hub in every active region."),
    "6.1.1": ("Ensure EBS volume encryption is enabled in all regions", 6, 1, "Automated", check_6_1_1,
              "Enable EBS encryption by default in every region."),
    "6.1.2": ("Ensure CIFS access is restricted to trusted networks", 6, 1, "Automated", check_6_1_2,
              "Restrict port 445 to trusted CIDRs."),
    "6.2": ("Ensure no NACLs allow ingress from 0.0.0.0/0 to remote server administration ports", 6, 1, "Automated", check_6_2,
            "Remove NACL allow rules for ports 22/3389 from 0.0.0.0/0."),
    "6.3": ("Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports", 6, 1, "Automated", check_6_3,
            "Remove SG rules exposing ports 22/3389 to 0.0.0.0/0."),
    "6.4": ("Ensure no security groups allow ingress from ::/0 to remote server administration ports", 6, 1, "Automated", check_6_4,
            "Remove SG rules exposing ports 22/3389 to ::/0."),
    "6.5": ("Ensure the default security group of every VPC restricts all traffic", 6, 2, "Automated", check_6_5,
            "Strip all rules from every default security group."),
    "6.6": ("Ensure routing tables for VPC peering are \"least access\"", 6, 2, "Manual", None,
            "Scope peering route tables to the specific required CIDRs."),
    "6.7": ("Ensure that the EC2 Metadata Service only allows IMDSv2", 6, 1, "Automated", check_6_7,
            "Set HttpTokens to required on all instances."),
    "6.8": ("Ensure VPC Endpoints are used for access to AWS Services", 6, 2, "Manual", None,
            "Use VPC endpoints for private access to AWS services."),
}

for _cid, (_title, _reqs) in MONITORING.items():
    REGISTRY[_cid] = (_title, 5, MONITORING_LEVEL[_cid], "Manual",
                      make_monitoring_check(_cid),
                      "Create a metric filter, alarm, and SNS subscription for these events.")

ORG_CONTROLS = {"2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6"}


def sort_key(cid):
    return [int(x) for x in cid.split(".")]


def run(cache, level, only):
    if cache.active_trail() is None:
        pass  # resolved lazily; monitoring checks report their own failure
    org_in_use = _org_in_use(cache)
    findings = []
    for cid in sorted(REGISTRY, key=sort_key):
        title, section, clevel, atype, fn, remediation = REGISTRY[cid]
        if only and cid not in only:
            continue
        if level == 1 and clevel != 1:
            continue
        f = Finding(cid, title, section, clevel, atype)
        f.remediation = remediation
        if cid in ORG_CONTROLS and not org_in_use:
            f.status = "na"
            f.detail = "AWS Organizations not in use for this account."
            findings.append(f)
            continue
        if fn is None:
            f.status = "manual"
            f.detail = "Requires human review; not machine-verifiable."
            findings.append(f)
            continue
        try:
            fn(cache, f)
        except ClientError as exc:
            f.status = "error"
            f.detail = "%s: %s" % (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
        except EndpointConnectionError as exc:
            f.status = "error"
            f.detail = str(exc)
        findings.append(f)
    return findings


def _org_in_use(cache):
    try:
        cache.client("organizations").describe_organization()
        return True
    except ClientError:
        return False


def build_report(cache, findings, level):
    counts = {}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    return {
        "benchmark": BENCHMARK,
        "account_id": cache.whoami(),
        "generated_at": now_utc().isoformat(),
        "regions_scanned": cache.regions(),
        "level_filter": level,
        "summary": counts,
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def main():
    ap = argparse.ArgumentParser(description="Read-only CIS AWS Foundations Benchmark v7.0.0 audit.")
    ap.add_argument("--profile", help="AWS named profile to use.")
    ap.add_argument("--regions", help="Comma-separated region allowlist.")
    ap.add_argument("--level", type=int, choices=(1, 2), default=1,
                    help="1 runs Level 1 only, 2 runs Level 1 and Level 2. Default 1.")
    ap.add_argument("--control", help="Comma-separated control IDs to run in isolation.")
    ap.add_argument("--output", default="cis_audit.json", help="Output JSON path.")
    args = ap.parse_args()

    region_filter = set(args.regions.split(",")) if args.regions else None
    only = set(args.control.split(",")) if args.control else None
    cache = Cache(profile=args.profile, region_filter=region_filter)

    try:
        cache.whoami()
    except Exception as exc:
        sys.stderr.write("Failed to establish AWS session: %s\n" % exc)
        return 2

    findings = run(cache, args.level, only)
    report = build_report(cache, findings, args.level)

    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2, default=str)

    s = report["summary"]
    sys.stderr.write("Account %s  Benchmark %s  Level %s\n" % (
        report["account_id"], BENCHMARK, args.level))
    sys.stderr.write("pass=%d fail=%d manual=%d na=%d error=%d  total=%d\n" % (
        s.get("pass", 0), s.get("fail", 0), s.get("manual", 0),
        s.get("na", 0), s.get("error", 0), report["total"]))
    sys.stderr.write("Report written to %s\n" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
