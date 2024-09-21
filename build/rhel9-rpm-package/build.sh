#!/usr/bin/env bash

die() {
  echo "${*}" 1>&2
  exit 1
}

if [[ -z "${1}" ]] ; then
  die "Please define \${1} as a feature of this script you want to use i.e. build or build_in_docker."
elif [[ -z "${2}" ]] ; then
  die "Please define \${2} as a spec file you want to build using this script."
fi

feature="${1}"
spec_file="${2}"
script_name="${0##*/}"
docker_script_work_directory="/srv"
docker_image_name="almalinux"
docker_image_tag="9.4"

_yum() {
  if [[ "$(id -u)" -eq 0 ]] ; then
    echo "yum"
  else
    echo "sudo yum"
  fi
}

build() {
  $(_yum) --assumeyes install rpmdevtools rpm-build dnf-utils
  spectool --get-files --directory "${PWD}/SOURCES" "${spec_file}"
  yum-builddep --assumeyes "${spec_file}"
  rpmbuild -bb --define "_topdir $(pwd)" "${spec_file}"
}

lint() {
  $(_yum) --assumeyes install rpmlint
  rpmlint -f .rpmlint -vi "${spec_file}"
}

run_in_docker() {
  [[ -z "${1}" ]] && die "Please specify a feature you want to run inside docker container."
  docker run \
    --mount "type=bind,source=${PWD},target=${docker_script_work_directory}" \
    --workdir "${docker_script_work_directory}" \
    --rm \
    --tty \
    "${docker_image_name}:${docker_image_tag}" \
    "${docker_script_work_directory}/${script_name}" "${1}" "${spec_file}"
}

lint_in_docker() {
  run_in_docker lint
}

build_in_docker() {
  run_in_docker build
}

"${feature}" "${spec_file}"
