# Copyright (c) 2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
import collections
import copy
import itertools
from os import path

import jsonschema
import six
import yaml

from sahara.i18n import _
from sahara.plugins import exceptions


def validate_instance(instance, validators, reconcile=True, **kwargs):
    """Runs all validators against the specified instance."""
    with instance.remote() as remote:
        for validator in validators:
            validator.validate(remote, reconcile=reconcile, **kwargs)


@six.add_metaclass(abc.ABCMeta)
class ImageValidator(object):
    """Validates the image spawned to an instance via a set of rules."""

    @abc.abstractmethod
    def validate(self, remote, reconcile=True, **kwargs):
        pass


@six.add_metaclass(abc.ABCMeta)
class SaharaImageValidatorBase(ImageValidator):
    """Base class for Sahara's native image validation."""

    DISTRO_KEY = 'SIV_DISTRO'
    RECONCILE_KEY = 'SIV_RECONCILE'

    ORDERED_VALIDATORS_SCHEMA = {
        "type": "array",
        "items": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": 1
        }
    }

    _DISTRO_FAMILES = {
        'centos': 'redhat',
        'fedora': 'redhat',
        'rhel': 'redhat',
        'ubuntu': 'debian'
    }

    @staticmethod
    def get_validator_map(custom_validator_map=None):
        default_validator_map = {
            'package': SaharaPackageValidator,
            'script': SaharaScriptValidator,
            'any': SaharaAnyValidator,
            'all': SaharaAllValidator,
            'os_case': SaharaOSCaseValidator,
        }
        if custom_validator_map:
            default_validator_map.update(custom_validator_map)
        return default_validator_map

    @classmethod
    def from_yaml(cls, yaml_path, validator_map=None, resource_roots=None):
        """Constructs and returns a validator from the provided yaml file.

        :param yaml_path: The path to a yaml file.
        :param validator_map: A map of validator name to class. Each class is
            expected to descend from SaharaImageValidator. This method will
            use the static map of validator name to class provided in the
            sahara.plugins.images module, updated with this map, to parse
            the appropriate classes to be used.
        :param resource_roots: The roots from which relative paths to
            resources (scripts and such) will be referenced. Any resource will
            be pulled from the first path in the list at which a file exists.
        """

        validator_map = validator_map or {}
        resource_roots = resource_roots or []
        validator_map = cls.get_validator_map(validator_map)
        with open(yaml_path, 'r') as yaml_stream:
            spec = yaml.safe_load(yaml_stream)
            return cls.from_spec(spec, validator_map, resource_roots)

    @classmethod
    def from_spec(cls, spec, validator_map, resource_roots):
        # Concrete subclasses should implement this factory method.
        pass

    @classmethod
    def from_spec_list(cls, specs, validator_map, resource_roots):
        validators = []
        for spec in specs:
            validator_class, validator_spec = cls.get_class_from_spec(
                spec, validator_map)
            validators.append(validator_class.from_spec(
                validator_spec, validator_map, resource_roots))
        return validators

    @classmethod
    def get_class_from_spec(cls, spec, validator_map):
        key, value = list(six.iteritems(spec))[0]
        validator_class = validator_map.get(key, None)
        if not validator_class:
            # TODO(egafford): i18n, how you to format; srsly?
            raise exceptions.ImageValidationSpecificationError(
                _("Validator type %s not found."))
        return validator_class, value

    class ValidationAttemptFailed(object):

        def __init__(self, exception):
            self.exception = exception

        def __bool__(self):
            return False

        def __nonzero__(self):
            return False

    def try_validate(self, remote, reconcile=True, env_map=None, **kwargs):
        try:
            self.validate(
                remote, reconcile=reconcile, env_map=env_map, **kwargs)
            return True
        except Exception as ex:
            return self.ValidationAttemptFailed(ex)


class SaharaImageValidator(SaharaImageValidatorBase):
    """The root of any tree of SaharaImageValidators.

    This validator serves as the root of the tree for SaharaImageValidators,
    and provides any needed initialization (such as distro retrieval.)
    """

    SPEC_SCHEMA = {
        "title": "SaharaImageValidator",
        "type": "object",
        "properties": {
            "validators": SaharaImageValidatorBase.ORDERED_VALIDATORS_SCHEMA
        },
        "required": ["validators"]
    }

    @classmethod
    def from_spec(cls, spec, validator_map, resource_roots):
        jsonschema.validate(spec, cls.SPEC_SCHEMA)
        specs = spec['validators']
        validator = SaharaAllValidator.from_spec(
            specs, validator_map, resource_roots)
        return cls(validator)

    def __init__(self, validator):
        self.validator = validator
        self.validators = validator.validators

    def validate(self, remote, reconcile=True, env_map=None, **kwargs):
        env_map = copy.deepcopy(env_map) if env_map else {}
        # TODO(egafford): Clean this up a lot. Exceptions, remove dep.
        raw_distro = remote.execute_command('lsb_release -is')
        distro = raw_distro[1].strip().lower()
        env_map[self.DISTRO_KEY] = distro
        env_map[self.RECONCILE_KEY] = 1 if reconcile else 0
        self.validator.validate(remote, reconcile=reconcile, env_map=env_map)


class SaharaPackageValidator(SaharaImageValidatorBase):

    class Package(object):

        def __init__(self, name, version=None):
            self.name = name
            self.version = version

        def __str__(self):
            return ("%s-%s" % (self.name, self.version)
                    if self.version else self.name)

    _SINGLE_PACKAGE_SCHEMA = {
        "oneOf": [
            {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 1,
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "version": {
                            "type": "string",
                            "minLength": 1
                        },
                    }
                },
            },
            {
                "type": "string",
                "minLength": 1
            }
        ]
    }

    SPEC_SCHEMA = {
        "title": "SaharaPackageValidator",
        "oneOf": [
            _SINGLE_PACKAGE_SCHEMA,
            {
                "type": "array",
                "items": _SINGLE_PACKAGE_SCHEMA,
                "minLength": 1
            }
        ]
    }

    @classmethod
    def _package_from_spec(cls, spec):
        if isinstance(spec, six.string_types):
            return cls.Package(spec, None)
        else:
            package, properties = list(six.iteritems(spec))[0]
            version = properties.get('version', None)
            return cls.Package(package, version)

    @classmethod
    def from_spec(cls, spec, validator_map, resource_roots):
        jsonschema.validate(spec, cls.SPEC_SCHEMA)
        packages = ([cls._package_from_spec(package_spec)
                     for package_spec in spec]
                    if isinstance(spec, list)
                    else [cls._package_from_spec(spec)])
        return cls(packages)

    def __init__(self, packages):
        self.packages = packages

    def validate(self, remote, reconcile=True, env_map=None, **kwargs):
        env_distro = env_map[self.DISTRO_KEY]
        env_family = self._DISTRO_FAMILES[env_distro]
        check, install = self._DISTRO_TOOLS[env_family]
        if not env_family:
            raise exceptions.ImageValidationError(
                _("Unknown distro: cannot verify or install packages."))
        # TODO(egafford): better logging and error reporting here, by a lot
        try:
            check(self, remote)
        # TODO(egafford): NO! Specific exception.
        except Exception:
            if reconcile:
                install(self, remote)
                check(self, remote)
            else:
                raise

    def _dpkg_check(self, remote):
        # TODO(egafford): Ensure that this fails if any fail at the cmdline
        check_cmd = "\n".join("dpkg -s %s" % str(package)
                              for package in self.packages)
        return _sudo(remote, check_cmd)

    def _rpm_check(self, remote):
        check_cmd = ("rpm -q %s" %
                     " ".join(str(package) for package in self.packages))
        return _sudo(remote, check_cmd)

    # TODO(egafford): Wrap dnf and extend map to allow variation within family
    def _yum_install(self, remote):
        install_cmd = (
            "yum install -y %s" %
            " ".join(str(package) for package in self.packages))
        _sudo(remote, install_cmd)

    def _apt_install(self, remote):
        # TODO(egafford): Ensure that apt-get functions w/ multiple args
        install_cmd = (
            "apt-get -y install %s" %
            " ".join(str(package) for package in self.packages))
        return _sudo(remote, install_cmd)

    _DISTRO_TOOLS = {
        "redhat": (_rpm_check, _yum_install),
        "debian": (_dpkg_check, _apt_install)
    }


class SaharaScriptValidator(SaharaImageValidatorBase):

    SPEC_SCHEMA = {
        "title": "SaharaScriptValidator",
        "oneOf": [
            {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 1,
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "env_vars": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        # TODO (egafford): Output
                    },
                }
            },
            {
                "type": "string"
            }
        ]
    }

    @classmethod
    def from_spec(cls, spec, validator_map, resource_roots):
        jsonschema.validate(spec, cls.SPEC_SCHEMA)

        if isinstance(spec, six.string_types):
            script_path = spec
            env_vars = []
        else:
            script_path, properties = list(six.iteritems(spec))[0]
            env_vars = properties.get('env_vars', [])

        script_contents = None
        for root in resource_roots:
            file_path = path.join(root, script_path)
            if path.isfile(file_path):
                with open(file_path, 'r') as script_stream:
                    script_contents = script_stream.read()
                    break

        if not script_contents:
            # TODO(egafford): i18n, what you do. What you do?
            raise exceptions.ImageValidationSpecificationError(
                _("Script %s not found in any resource roots."))

        return SaharaScriptValidator(script_contents, env_vars)

    def __init__(self, script_contents, env_vars=None):
        self.script_contents = script_contents
        self.env_vars = env_vars or []

    def validate(self, remote, reconcile=True, env_map=None, **kwargs):
        # TODO(egafford): Does our remote provide an env map? If so, use it.
        env_prefix = "\n".join("export %s=%s" % (key, value) for (key, value)
                               in six.iteritems(env_map)) + '\n\n'
        # TODO(egafford): Script path.
        _sudo(remote, env_prefix + self.script_contents)


@six.add_metaclass(abc.ABCMeta)
class SaharaAggregateValidator(SaharaImageValidatorBase):

    SPEC_SCHEMA = SaharaImageValidator.ORDERED_VALIDATORS_SCHEMA

    @classmethod
    def from_spec(cls, spec, validator_map, resource_roots):
        jsonschema.validate(spec, cls.SPEC_SCHEMA)
        validators = cls.from_spec_list(spec, validator_map, resource_roots)
        return cls(validators)

    def __init__(self, validators):
        self.validators = validators


class SaharaAnyValidator(SaharaAggregateValidator):

    def validate(self, remote, reconcile=True, env_map=None, **kwargs):
        valid = (
            any(
                validator.try_validate(
                    remote, reconcile=False, env_map=env_map)
                for validator in self.validators)
            or
            (reconcile and any(
                validator.try_validate(
                    remote, reconcile=True, env_map=env_map)
                for validator in self.validators))
        )
        if not valid:
            # TODO(egafford): Logging. Spec and exception info.
            raise exceptions.ImageValidationError("All validations failed.")


class SaharaAllValidator(SaharaAggregateValidator):

    def validate(self, remote, reconcile=True, env_map=None, **kwargs):
        for validator in self.validators:
            validator.validate(remote, reconcile=reconcile, env_map=env_map)


class SaharaOSCaseValidator(SaharaImageValidatorBase):

    _distro_tuple = collections.namedtuple('Distro', ['distro', 'validator'])

    SPEC_SCHEMA = {
        "type": "array",
        "minLength": 1,
        "items": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": 1,
            "additionalProperties":
                SaharaImageValidator.ORDERED_VALIDATORS_SCHEMA,
        }
    }

    @classmethod
    def from_spec(cls, spec, validator_map, resource_roots):
        jsonschema.validate(spec, cls.SPEC_SCHEMA)
        distros = itertools.chain(*(six.iteritems(distro_spec)
                                    for distro_spec in spec))
        distros = [
            cls._distro_tuple(key, SaharaAllValidator.from_spec(
                value, validator_map, resource_roots))
            for (key, value) in distros]
        return cls(distros)

    def __init__(self, distros):
        self.distros = distros

    def validate(self, remote, reconcile=True, env_map=None, **kwargs):
        env_distro = env_map[self.DISTRO_KEY]
        family = self._DISTRO_FAMILES.get(env_distro)
        matches = {env_distro, family} if family else {env_distro}
        for distro, validator in self.distros:
            if distro in matches:
                validator.validate(
                    remote, reconcile=reconcile, env_map=env_map)
                break


def _sudo(remote, cmd, **kwargs):
    remote.execute_command(cmd, run_as_root=True, **kwargs)
