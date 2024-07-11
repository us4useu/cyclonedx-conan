#!/usr/bin/env python3
# encoding: utf-8

# This file is part of CycloneDX Conan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

import argparse
import json
import os.path
import sys
from uuid import uuid4
from conans.client.conan_api import Conan, ProfileData
from conans.client.command import Command as ConanCommand, OnceArgument, Extender, _add_common_install_arguments
from conans.client.graph.graph import DepsGraph, Node
from conans.client.output import ConanOutput, colorama_initialize
from conans.errors import ConanMigrationError, ConanException
from packageurl import PackageURL
from typing import Set, Dict, Any


def sanitize(value: str) -> str:
    return f"{value}" if value else ""


class CycloneDXCommand:
    # Parsed Arguments
    _arguments: argparse.Namespace

    def __init__(self, args: Dict[str, Any]):
        self._arguments = args

    @staticmethod
    def get_arg_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="CycloneDX SBOM Generator")

        parser.add_argument("path_or_reference", help="Path to a folder containing a recipe"
                            " (conanfile.py or conanfile.txt) or to a recipe file. e.g., "
                            "./my_project/conanfile.txt. It could also be a reference")
        parser.add_argument("-if", "--install-folder", action=OnceArgument,
                            help="local folder containing the conaninfo.txt and conanbuildinfo.txt "
                            "files (from a previous conan install execution). Defaulted to "
                            "current folder, unless --profile, -s or -o is specified. If you "
                            "specify both install-folder and any setting/option "
                            "it will raise an error.")
        dry_build_help = ("Apply the --build argument to output the information, "
                          "as it would be done by the install command")
        parser.add_argument("-db", "--dry-build", action=Extender, nargs="?", help=dry_build_help)
        output_help="Output file path for your SBOM (set to \"-\" to output to STDOUT)"
        parser.add_argument(
            "--output", action="store", metavar="FILE_PATH", default="-", required=False,
            help=output_help, dest="output_file"
        )
        exclude_dev_help = "Exclude development dependencies from the BOM"
        parser.add_argument(
            "--exclude-dev", action="store_true",
            help=exclude_dev_help, dest="exclude_dev"
        )
        build_help = ("Given a build policy, return an ordered list of packages that would be built"
                      " from sources during the install command")

        update_help = "Will check if updates of the dependencies exist in the remotes " \
                      "(a new version that satisfies a version range, a new revision or a newer " \
                      "recipe if not using revisions)."
        _add_common_install_arguments(parser, update_help=update_help, build_help=build_help)

        return parser

    def execute(self):
        try:
            conan_api = Conan(output=ConanOutput(sys.stderr, sys.stderr, colorama_initialize()))
        except ConanMigrationError:  # Error migrating
            sys.exit(1)
        except ConanException as e:
            sys.stderr.write("Error in Conan initialization: {}".format(e))
            sys.exit(1)
        conan_command = ConanCommand(conan_api)

        profile_build = ProfileData(profiles=self._get_argument("profile_build"),
                                    settings=self._get_argument("settings_build"),
                                    options=self._get_argument("options_build"),
                                    env=self._get_argument("env_build"),
                                    conf=self._get_argument("conf_build"))
        data = conan_command._conan.info(
            self._get_argument("path_or_reference"),
            remote_name=self._get_argument("remote"),
            settings=self._get_argument("settings_host"),
            options=self._get_argument("options_host"),
            env=self._get_argument("env_host"),
            profile_names=self._get_argument("profile_host"),
            conf=self._get_argument("conf_host"),
            profile_build=profile_build,
            update=self._get_argument("update"),
            install_folder=self._get_argument("install_folder"),
            build=self._get_argument("dry_build"),
            lockfile=self._get_argument("lockfile"))

        deps_graph: DepsGraph = data[0]

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:" + str(uuid4()),
            "version": 1,
            "metadata": {
                "component": {
                    "bom-ref": "unknown@0.0.0",
                    "type": "library",
                    "name": "unknown",
                    "version": "0.0.0",
                },
            },
            "components": [],
            "dependencies": [],
        }

        required_ids = set()
        if self._get_argument("exclude_dev"):
            visited_ids = set()
            to_visit: Set[Node] = set(node for node in deps_graph.nodes if node.ref is None)
            while to_visit:
                node = to_visit.pop()
                if node.id in visited_ids:
                    continue
                visited_ids.add(node.id)
                required_ids.add(node.id)
                for dependency in node.dependencies:
                    if str(dependency.dst.id) in node.graph_lock_node.requires:
                        to_visit.add(dependency.dst)

        for node in deps_graph.nodes:
            if node.ref is None:
                # top level component
                bom["metadata"]["component"]["name"] = os.path.basename(os.path.dirname(node.path))
                bom["metadata"]["component"]["bom-ref"] = bom["metadata"]["component"]["name"] + "@" + bom["metadata"]["component"]["version"]
                dependencies = {
                    "ref": bom["metadata"]["component"]["bom-ref"],
                    "dependsOn": [],
                }
                for dependency in node.dependencies:
                    purl = get_purl(dependency.dst.remote, dependency.dst.ref)
                    if (
                        self._get_argument("exclude_dev")
                        and str(dependency.dst.id) not in required_ids
                    ):
                        continue
                    dependencies["dependsOn"].append(str(purl))
                bom["dependencies"].append(dependencies)
            else:
                if (
                    self._get_argument("exclude_dev")
                    and str(node.id) not in required_ids
                ):
                    continue
                purl = get_purl(node.remote, node.ref)

                component = {
                    "bom-ref": str(purl),
                    "type": "library",
                    "name": node.conanfile.name,
                    "version": node.conanfile.version,
                    "description": sanitize(node.conanfile.description),
                    # For now it seems that there is no author here ...
                    # "author": sanitize(node.conanfile.author),
                    "purl": str(purl),
                    "externalReferences": self.get_external_references(node.conanfile),
                    "licenses": self.get_licenses(node.conanfile)
                }
                if node.ref.user:
                    component["namespace"] = node.ref.user
                bom["components"].append(component)
                dependencies = {
                    "ref": component["bom-ref"],
                    "dependsOn": [],
                }
                for dependency in node.dependencies:
                    if (
                        self._get_argument("exclude_dev")
                        and str(dependency.dst.id) not in required_ids
                    ):
                        continue
                    dep_purl = get_purl(dependency.dst.remote, dependency.dst.ref)
                    dependencies["dependsOn"].append(str(dep_purl))
                bom["dependencies"].append(dependencies)

        output = json.dumps(bom, indent=2)
        if self._get_argument("output_file") == "-" or not self._get_argument("output_file"):
            print(output)
        else:
            with open(self._get_argument("output_file"), "w") as file:
                file.write(output)

    def get_licenses(self, conanfile):
        if conanfile.license:
            licenses = conanfile.license
            if not (isinstance(licenses, list) or isinstance(licenses, tuple)):
                licenses = [licenses]
            return [
                {
                    "license": {"id": l}
                }
                for l in licenses
            ]
        else:
            return []

    def get_external_references(self, conanfile):
        if conanfile.homepage:
            return [
                {
                    "type": "website",
                    "url": conanfile.homepage
                }
            ]
        else:
            return []

    def _get_argument(self, key: str):
        return self._arguments.get(key, None)


def get_purl(remote, ref):
    qualifiers = {
        "repository_url": "localhost" if remote is None else remote.url,
    }
    if ref.user:
        qualifiers["channel"] = ref.channel
    purl = PackageURL(type="conan", namespace=ref.user, name=ref.name, version=ref.version, qualifiers=qualifiers)
    return purl


def main():
    parser = CycloneDXCommand.get_arg_parser()
    args = parser.parse_args()
    CycloneDXCommand(vars(args)).execute()


if __name__ == "__main__":
    main()
