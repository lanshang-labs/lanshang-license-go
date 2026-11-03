# Lanshang License Go

Framework-independent Go SDK for remote product licensing. MIT licensed.

## Integration

Pin the server URL and Ed25519 public keys in the product build. Keep the license
key in server-side deployment secrets. Persist a distinct instance identity and
cache per deployment using `LoadOrCreateInstance` and `Config.CachePath`.

```go
instance, err := license.LoadOrCreateInstance("var/license/instance")
if err != nil { return err }
client, err := license.New(license.Config{
    ServerURL: "https://auth.wearloom.cn",
    Product: "your-product",
    Organization: organization,
    Key: secretLicenseKey,
    InstanceID: instance,
    PublicKeys: trustedBuildKeys,
    CachePath: "var/license/lease.json",
})
if err != nil { return err }
_ = client.Refresh(ctx)
go client.Run(ctx)
// Mount diagnostics separately. Wrap every HTTP/API/MCP entry point.
handler := client.Middleware(businessHandler)
_ = handler
```

`Status` validates locally without a network request. `Run` refreshes hourly and
retries transient failures every minute. Signed credentials expire within 24 hours,
never later than the license itself. Recognized revocation, suspension, expiry,
invalid key and instance-limit responses erase cached authorization, including
across restarts. Server unavailability can use only an existing valid signature.
Redirects are refused. HTTP is supported explicitly for loopback development.

Call `Release` when transferring an instance, stop its refresh loop, then activate
the new deployment. A running process with the old key can reactivate after release,
so stop it or reset the license key when decommissioning an untrusted deployment.
Keep customer data and accepted jobs intact on denial. Provide health and license
recovery routes outside middleware. An import alone cannot protect unwrapped routes.

Cached credentials are readable signed statements, not encryption. Instance IDs
are deployment identities, not hardware anti-tamper protection. A customer who can
replace your executable can alter client enforcement. Protect server signing keys
and keep old public keys pinned until their last 24-hour credential has expired.

`make test` runs unit and concurrent lifecycle tests. `make check` runs Go vet.
