This configs folder contains configs which are built into images. The contents may appear similar to `strelka/configs`
but that folder is left as is to cleanly receive/make updates from/to the upstream. These configs use a slightly 
different structure than the upstream in order to disconnect rules/scan configurations from runtime configurations 
(those will still be injected by the runner).

Some of this content also appears similar to content in `strelka/misc/kubernets` -- that folder is example K8S manifests
and includes inlined configuration (which currently differs slightly from other example configurations).

To use these:
* Change scanners in the main backend config to `scanners: '/strelka/config/scanners.yaml'` (instead of a list of objs)
* Any scanner which supports the passwords file:
  * `password_file: '/strelka/config/passwords.dat' `
* Change `tasting` in main backend config to `yara_rules: '/etc/strelka/taste/'`

