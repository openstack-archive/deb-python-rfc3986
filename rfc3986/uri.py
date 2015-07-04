# -*- coding: utf-8 -*-
# Copyright (c) 2014 Rackspace
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
from collections import namedtuple

from .compat import to_str
from .exceptions import InvalidAuthority, ResolutionError
from .misc import (
    ABSOLUTE_URI_MATCHER, FRAGMENT_MATCHER, IPv4_MATCHER, PATH_MATCHER,
    QUERY_MATCHER, SCHEME_MATCHER, SUBAUTHORITY_MATCHER, URI_MATCHER,
    URI_COMPONENTS, merge_paths, subauthority_splitter,
    valid_ipv4_host_address
    )
from .normalizers import (
    encode_component, normalize_scheme, normalize_authority, normalize_path,
    normalize_query, normalize_fragment
    )


class URIReference(namedtuple('URIReference', URI_COMPONENTS)):
    slots = ()

    def __new__(cls, scheme, authority, path, query, fragment, userinfo=None,
                host=None, port=None, encoding='utf-8'):
        ref = super(URIReference, cls).__new__(
            cls,
            scheme or None,
            authority or None,
            path or None,
            query or None,
            fragment or None,
            userinfo,
            host,
            port)
        ref.encoding = encoding
        return ref

    def __eq__(self, other):
        other_ref = other
        if isinstance(other, tuple):
            other_ref = URIReference(*other)
        elif not isinstance(other, URIReference):
            try:
                other_ref = URIReference.from_string(other)
            except TypeError:
                raise TypeError(
                    'Unable to compare URIReference() to {0}()'.format(
                        type(other).__name__))

        # See http://tools.ietf.org/html/rfc3986#section-6.2
        naive_equality = tuple(self) == tuple(other_ref)
        return naive_equality or self.normalized_equality(other_ref)

    @classmethod
    def from_string(cls, uri_string, encoding='utf-8'):
        """Parse a URI reference from the given unicode URI string.

        :param str uri_string: Unicode URI to be parsed into a reference.
        :param str encoding: The encoding of the string provided
        :returns: :class:`URIReference` or subclass thereof
        """
        userinfo = host = port = None
        uri_string = to_str(uri_string, encoding)

        split_uri = URI_MATCHER.match(uri_string).groupdict()
        if split_uri['authority']:
            userinfo, host, port = subauthority_splitter(
                split_uri['authority'], encoding
            )
            if userinfo is None and host is None and port is None:
                raise InvalidAuthority(split_uri['authority'].encode(encoding))
        return cls(split_uri['scheme'], split_uri['authority'],
                   encode_component(split_uri['path'], encoding),
                   encode_component(split_uri['query'], encoding),
                   encode_component(split_uri['fragment'], encoding),
                   userinfo=userinfo, host=host, port=port, encoding=encoding)

    def authority_info(self):
        """Returns a dictionary with the ``userinfo``, ``host``, and ``port``.

        .. warning:: This has been deprecated as of version 0.3.0

        If the authority is not valid, it will raise a ``InvalidAuthority``
        Exception.

        :returns:
            ``{'userinfo': 'username:password', 'host': 'www.example.com',
            'port': '80'}``
        :rtype: dict
        :raises InvalidAuthority: If the authority is not ``None`` and can not
            be parsed.
        """
        if not self.authority:
            return {'userinfo': None, 'host': None, 'port': None}

        subauthority = subauthority_splitter(self.authority, self.encoding)
        if all(i is None for i in subauthority):
            # In this case, we have an authority that was parsed from the URI
            # Reference, but it cannot be further parsed by our
            # SUBAUTHORITY_MATCHER. In this case it must not be a valid
            # authority.
            raise InvalidAuthority(self.authority.encode(self.encoding))

        keys = ('userinfo', 'host', 'port')
        return dict(zip(keys, subauthority))

    def is_absolute(self):
        """Determine if this URI Reference is an absolute URI.

        See http://tools.ietf.org/html/rfc3986#section-4.3 for explanation.

        :returns: ``True`` if it is an absolute URI, ``False`` otherwise.
        :rtype: bool
        """
        return bool(ABSOLUTE_URI_MATCHER.match(self.unsplit()))

    def is_valid(self, **kwargs):
        """Determines if the URI is valid.

        :param bool require_scheme: Set to ``True`` if you wish to require the
            presence of the scheme component.
        :param bool require_authority: Set to ``True`` if you wish to require
            the presence of the authority component.
        :param bool require_path: Set to ``True`` if you wish to require the
            presence of the path component.
        :param bool require_query: Set to ``True`` if you wish to require the
            presence of the query component.
        :param bool require_fragment: Set to ``True`` if you wish to require
            the presence of the fragment component.
        :returns: ``True`` if the URI is valid. ``False`` otherwise.
        :rtype: bool
        """
        validators = [
            (self.scheme_is_valid, kwargs.get('require_scheme', False)),
            (self.authority_is_valid, kwargs.get('require_authority', False)),
            (self.path_is_valid, kwargs.get('require_path', False)),
            (self.query_is_valid, kwargs.get('require_query', False)),
            (self.fragment_is_valid, kwargs.get('require_fragment', False)),
            ]
        return all(v(r) for v, r in validators)

    def _is_valid(self, value, matcher, require):
        if require:
            return (value is not None
                    and matcher.match(value))

        # require is False and value is not None
        return value is None or matcher.match(value)

    def authority_is_valid(self, require=False):
        """Determines if the authority component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the authority is valid. ``False`` otherwise.
        :rtype: bool
        """
        try:
            self.authority_info()
        except InvalidAuthority:
            return False

        is_valid = self._is_valid(self.authority,
                                  SUBAUTHORITY_MATCHER,
                                  require)

        # Ensure that IPv4 addresses have valid bytes
        if is_valid and self.host and IPv4_MATCHER.match(self.host):
            return valid_ipv4_host_address(self.host)

        # Perhaps the host didn't exist or if it did, it wasn't an IPv4-like
        # address. In either case, we want to rely on the `_is_valid` check,
        # so let's return that.
        return is_valid

    def scheme_is_valid(self, require=False):
        """Determines if the scheme component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the scheme is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.scheme, SCHEME_MATCHER, require)

    def path_is_valid(self, require=False):
        """Determines if the path component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the path is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.path, PATH_MATCHER, require)

    def query_is_valid(self, require=False):
        """Determines if the query component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the query is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.query, QUERY_MATCHER, require)

    def fragment_is_valid(self, require=False):
        """Determines if the fragment component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the fragment is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.fragment, FRAGMENT_MATCHER, require)

    def normalize(self):
        """Normalize this reference as described in Section 6.2.2

        This is not an in-place normalization. Instead this creates a new
        URIReference.

        :returns: A new reference object with normalized components.
        :rtype: URIReference
        """
        subauthority = (self.userinfo, self.host, self.port)
        if self.authority and all(i is None for i in subauthority):
            # NOTE(sigmavirus24): This is a backwards compatibility shim for
            # users who do not explicitly set userinfo, host, or port
            subauthority = subauthority_splitter(self.authority,
                                                 self.encoding)
        # See http://tools.ietf.org/html/rfc3986#section-6.2.2 for logic in
        # this method.
        return URIReference(normalize_scheme(self.scheme or ''),
                            normalize_authority(subauthority),
                            normalize_path(self.path or ''),
                            normalize_query(self.query or ''),
                            normalize_fragment(self.fragment or ''))

    def normalized_equality(self, other_ref):
        """Compare this URIReference to another URIReference.

        :param URIReference other_ref: (required), The reference with which
            we're comparing.
        :returns: ``True`` if the references are equal, ``False`` otherwise.
        :rtype: bool
        """
        return tuple(self.normalize()) == tuple(other_ref.normalize())

    def resolve_with(self, base_uri, strict=False):
        """Use an absolute URI Reference to resolve this relative reference.

        Assuming this is a relative reference that you would like to resolve,
        use the provided base URI to resolve it.

        See http://tools.ietf.org/html/rfc3986#section-5 for more information.

        :param base_uri: Either a string or URIReference. It must be an
            absolute URI or it will raise an exception.
        :returns: A new URIReference which is the result of resolving this
            reference using ``base_uri``.
        :rtype: :class:`URIReference`
        :raises ResolutionError: If the ``base_uri`` is not an absolute URI.
        """
        if not isinstance(base_uri, URIReference):
            base_uri = URIReference.from_string(base_uri)

        if not base_uri.is_absolute():
            raise ResolutionError(base_uri)

        # This is optional per
        # http://tools.ietf.org/html/rfc3986#section-5.2.1
        base_uri = base_uri.normalize()

        # The reference we're resolving
        resolving = self

        if not strict and resolving.scheme == base_uri.scheme:
            resolving = resolving.copy_with(scheme=None)

        # http://tools.ietf.org/html/rfc3986#page-32
        if resolving.scheme is not None:
            target = resolving.copy_with(path=normalize_path(resolving.path))
        else:
            if resolving.authority is not None:
                target = resolving.copy_with(
                    scheme=base_uri.scheme,
                    path=normalize_path(resolving.path)
                )
            else:
                if resolving.path is None:
                    if resolving.query is not None:
                        query = resolving.query
                    else:
                        query = base_uri.query
                    target = resolving.copy_with(
                        scheme=base_uri.scheme,
                        authority=base_uri.authority,
                        path=base_uri.path,
                        query=query
                    )
                else:
                    if resolving.path.startswith('/'):
                        path = normalize_path(resolving.path)
                    else:
                        path = normalize_path(
                            merge_paths(base_uri, resolving.path)
                        )
                    target = resolving.copy_with(
                        scheme=base_uri.scheme,
                        authority=base_uri.authority,
                        path=path,
                        query=resolving.query
                    )
        return target

    def unsplit(self):
        """Create a URI string from the components.

        :returns: The URI Reference reconstituted as a string.
        :rtype: str
        """
        # See http://tools.ietf.org/html/rfc3986#section-5.3
        result_list = []
        if self.scheme:
            result_list.extend([self.scheme, ':'])
        if self.authority:
            result_list.extend(['//', self.authority])
        if self.path:
            result_list.append(self.path)
        if self.query:
            result_list.extend(['?', self.query])
        if self.fragment:
            result_list.extend(['#', self.fragment])
        return ''.join(result_list)

    def copy_with(self, **kwargs):
        return self._replace(**kwargs)
