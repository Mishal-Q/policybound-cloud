# Targets that work right now, with nothing beyond opa and python3:
#   make test-policy
#   make test-drift
#   make test
#
# Targets that need a real terraform binary and AWS credentials, neither
# of which were available while this was built (see docs/limitations.md):
#   make tf-validate
#   make tf-plan
#
# I'm keeping both kinds in one Makefile rather than only listing the
# ones that work, because the second group is exactly what you should
# run first once you have Terraform and AWS set up.

.PHONY: test test-policy test-drift tf-fmt tf-validate tf-plan lambda-package clean

OPA ?= opa
TF ?= terraform

test: test-policy test-drift

test-policy:
	$(OPA) test policies/ -v

test-drift:
	cd drift/tests && python3 -m pytest -v

tf-fmt:
	$(TF) fmt -check -recursive .

tf-validate:
	cd environments/dev && $(TF) init -backend=false && $(TF) validate

tf-plan:
	cd environments/dev && $(TF) plan

lambda-package:
	mkdir -p drift/detector/build
	cd drift/detector && pip install -r requirements.txt -t build/ --quiet
	cp drift/detector/*.py drift/detector/build/
	cp drift/classifier/*.py drift/detector/build/
	cp remediation/exceptions.py remediation/exceptions.yaml drift/detector/build/
	cd drift/detector/build && zip -r ../build/drift_detector.zip . -x '*.pyc'

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} \;
	find . -name '.pytest_cache' -type d -prune -exec rm -rf {} \;
	rm -rf drift/detector/build
