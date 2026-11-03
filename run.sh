#!/usr/bin/env bash

set -x
taosc_llm_path=/home/binradar/code/binradar-dev/utils/taosc-llm
binradar_path=/home/binradar/code/binradar-dev
cd /home/binradar/code/binradar-dev/benchmarks/loftix/binutils/CVE-2017-14745

# Run taosc-fix-prepare (tentative name)
# -> generate workdir with patch-location

# Run binradar --generate-concrete
uv run --project $binradar_path binradar-setup setup -w workdir-0.1.24 --generate-concrete
uv run --project $binradar_path binradar -w workdir-0.1.24 --generate-concrete --run-prefix br-gen-con --timeout 7200

# Run taosc-fix
# -> generate patch-format, patch-destination, etc.

# Run binradar --generate-binradar
uv run --project $binradar_path binradar-setup setup -w workdir-0.1.24 --generate-binradar
uv run --project $binradar_path binradar -w workdir-0.1.24 --generate-binradar --run-prefix br-gen-bin --timeout 7200

# Run taosc-llm-setup
uv run --project $taosc_llm_path taosc-llm-setup -c config.env -w workdir-0.1.24 \
  --concrete-run workdir-0.1.24/out/br-gen-con-00000 \
  --binradar-run workdir-0.1.24/out/br-gen-bin-00000 \
  --rea /gnu/store/mwqz9kghrpy1jh2ny7xj2p3yw5m4slsj-taosc-llm-rea-6.8.0/bin/rea \
  --output workdir-0.1.24/out/dataset-0.1.24

# Run taosc-llm
uv run --project $taosc_llm_path taosc-llm --provider-env $taosc_llm_path/.env --pi-sdk-root $taosc_llm_path/thirdparty/pi --dataset workdir-0.1.24/out/dataset-0.1.24 --output workdir-0.1.24/out/taosc-llm-result

