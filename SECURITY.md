# Security

## Every key in this repository is fake

SecureGate is a secret scanner, so its tests and demos are full of things that look like keys. None of them is real:

- **ACME Pay does not exist.** It is the payment provider invented for the demos. Its `acme_live_` and `acme_test_` tokens are made at random whenever a demo needs one, and unlock nothing.
- **The other fake keys are built when they are needed.** The demo project's Stripe, AWS, GitHub and private keys, and the tests' fakes, are put together at runtime from a known beginning and random characters. No file in this repository holds a key-shaped string: a test scans the repository itself, and SecureGate's own merge gate checks every pull request.
- **The demo pull requests held fake ACME Pay tokens only.** They showed the merge gate at work; they were closed and their branches deleted at the close-out. GitHub keeps closed pull requests, which is harmless here.

## Report a problem

Found a real secret in this repository, or a way to make SecureGate show a whole secret, let a blocked one through, or pass when it should fail? Please report it **privately**: on GitHub, open this repository's **Security** tab and choose **Report a vulnerability**. Don't open a public issue for it.

If you report a real secret, don't paste it: say where it is (the file and the commit), masked like `sk_l****562d`. A leaked key is fixed by revoking it at its provider, not by deleting the line.

## Support

SecureGate is finished and **not actively maintained**. It was built for Microsoft Innovate 2026 (Problem Statement 24), and 1.0.0 is its last release. Reports reach the owner, but there is no promise of a fix or of a new release.

| Version | Supported |
|---|---|
| 1.0.0 | As it is: reports are read, fixes are not promised |
| before 1.0.0 | No |
