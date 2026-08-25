# Security policy

Please do not open public issues for vulnerabilities.

Use GitHub's **Report a vulnerability** flow in the Security tab of this
repository. Include the affected version, configuration, impact, and a minimal
reproducer when possible. Reports are acknowledged on a best-effort basis.

The project has not undergone an independent security audit. Treat it as one
component of a defense-in-depth ingress design, keep the health listener on
loopback, validate firewall policy separately, and test changes under realistic
load before production rollout.
