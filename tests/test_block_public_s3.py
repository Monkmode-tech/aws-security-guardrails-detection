import os
import unittest
from unittest import mock

from fakes import FakeS3, FakeSNS, load_handler

mod = load_handler("block_public_s3")

BUCKET = "example-bucket"
ALL_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def event(name="DeletePublicAccessBlock", bucket=BUCKET):
    return {
        "detail": {
            "eventName": name,
            "userIdentity": {"arn": "arn:aws:iam::111122223333:user/dev"},
            "sourceIPAddress": "203.0.113.10",
            "requestParameters": {"bucketName": bucket},
        }
    }


@mock.patch.dict(os.environ, {"ALERT_TOPIC_ARN": "arn:aws:sns:us-east-2:111122223333:alerts", "DRY_RUN": "false"})
class Handler(unittest.TestCase):
    def test_restores_block_when_configuration_deleted(self):
        s3, sns = FakeS3(block=None, tags=None), FakeSNS()
        result = mod.handler(event(), s3=s3, sns=sns)

        self.assertEqual(result["status"], "remediated")
        self.assertEqual(sorted(result["settingsRestored"]), sorted(ALL_ON))
        put = s3.called("put_public_access_block")
        self.assertEqual(put[0]["PublicAccessBlockConfiguration"], ALL_ON)
        self.assertEqual(len(sns.called("publish")), 1)

    def test_restores_only_missing_settings_are_reported(self):
        partial = dict(ALL_ON, RestrictPublicBuckets=False, BlockPublicPolicy=False)
        result = mod.handler(event("PutPublicAccessBlock"), s3=FakeS3(block=partial), sns=FakeSNS())
        self.assertEqual(sorted(result["settingsRestored"]), ["BlockPublicPolicy", "RestrictPublicBuckets"])

    def test_already_blocked_bucket_is_compliant(self):
        s3, sns = FakeS3(block=dict(ALL_ON)), FakeSNS()
        self.assertEqual(mod.handler(event("PutBucketPolicy"), s3=s3, sns=sns)["status"], "compliant")
        self.assertEqual(s3.called("put_public_access_block"), [])
        self.assertEqual(sns.called("publish"), [])

    def test_exempt_bucket_is_skipped(self):
        s3 = FakeS3(block=None, tags={"AllowPublicAccess": "true"})
        self.assertEqual(mod.handler(event(), s3=s3, sns=FakeSNS())["status"], "skipped")
        self.assertEqual(s3.called("put_public_access_block"), [])

    def test_deleted_bucket_is_skipped(self):
        self.assertEqual(mod.handler(event(), s3=FakeS3(exists=False), sns=FakeSNS())["status"], "skipped")

    def test_event_without_bucket_is_skipped(self):
        self.assertEqual(mod.handler({"detail": {}}, s3=FakeS3(), sns=FakeSNS())["status"], "skipped")

    def test_dry_run_changes_nothing(self):
        s3 = FakeS3(block=None)
        with mock.patch.dict(os.environ, {"DRY_RUN": "true"}):
            result = mod.handler(event(), s3=s3, sns=FakeSNS())
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(s3.called("put_public_access_block"), [])


if __name__ == "__main__":
    unittest.main()
