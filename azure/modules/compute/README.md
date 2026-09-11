# Intentionally empty

None of the six selected cross-cloud invariants need a compute resource
on the Azure side -- public exposure, network reachability, encryption,
identity/RBAC scope, region, and tags are all demonstrated through the
Storage Account, NSG, and Role Assignment resources in the other
modules. Adding a VM or App Service here wouldn't add evidence for any
of the six, it would just add a resource to maintain.

If a future invariant needs a compute resource (e.g. checking that a VM
doesn't have a public IP), this is where it goes. Left as a labeled
placeholder rather than silently omitted from the directory tree, since
the original project structure named this module explicitly.
