# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
The Rekall Memory Forensics entity layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"


from rekall import obj
from rekall import utils


class Entity(object):
    """Entity is an abstraction of things like Process, User or Connection.

    Entities are composed of an identity, like PID, username or memory address
    of a socket, and a list of components, which are just named tuples that
    describe the identity.

    Entities are not intended to be subclassed - they favor composition over
    inheritance [1].

    ### Behavior: Merging

    The only behavior defined on Entity is the 'merge' class method. If the
    same identity is discovered twice (for example, a user is found in a list
    of processes and in a registry key) all of the information learned about it
    can be merged into a single entity that contains everything we know about
    the thing.

    ### Immutability

    Entites and components are intended to be immutable, copy-on-write. This
    is currently not enforced by this class. Altering an entity or a component
    may lead to undefined behavior. All methods that appear to alter the entity
    are, in reality, returning new instances.

    ### Associations/Relationships

    Some entities have components that define their relationship to other
    entities. For example, a process has many open handles, and a connection
    is associated with a handle.

    In these cases, the components store the identity object, NOT the
    entity(ies) they represent.

    ### State/constructor arguments

    identity: An object that uniquely identifies an entity. Must support
        __hash__, __eq__, __ne__ and __unicode__.

    components: All information about the identity.

    collectors: A (frozen)set of collectors, which are all the ways we learned
        information about the identity. Joined on merging.

    copies_count: The number of times this identity was discovered by different
        collectors. Incremented on merging.

    ### References:

    1: http://en.wikipedia.org/wiki/Composition_over_inheritance

    Also see: http://en.wikipedia.org/wiki/Entity_component_system
    """

    def __init__(self, identity, components, collectors=frozenset(),
                 copies_count=1):
        self.identity = identity
        self.components = components
        self.collectors = collectors
        self.copies_count = copies_count
    
    def __hash__(self):
        return hash(self.identity)

    def __eq__(self, other):
        return self.identity == other.identity

    def __ne__(self, other):
        return not self.__eq__(other)

    def m(self, attr, component=None):
        """Retrieve a property of a component.

        Shorthand syntax:
            entity.m("component.property")

        Faster:
            entity.m("property", component="component")

        It is not an error to request a property or a component that doesn't
        exist - you will get a NoneObject.
        """
        if component is None:
            component, attr = attr.split(".")

        component_data = self.components.get(
            key=component,
            default=obj.NoneObject(
                "Entity %s has no component %s." %
                (self, component)
            )
        )

        return getattr(
            object=component_data,
            name=attr,
            default=obj.NoneObject(
                "Component %s has no attribute %s." %
                (component, attr)
            )
        )

    def __unicode__(self):
        return self.identity
    
    def __str__(self):
        return self.__unicode__()

    @classmethod
    def merge(cls, x, y):
        if x != y:
            raise AttributeError(
                "Cannot merge entities with different identities.")

        return Entity(
            identity=x.identity,
            components=utils.MergeNamedTuples(
                x.components,
                y.components,
                preserving=True,
            ),
            copies_count=x.copies_count + y.copies_count,
            collectors=x.collectors | y.collectors,
        )


class EntityCache(object):
    """Per-session register of entities."""

    def __init__(self, session):
        self.session = session
        
        # Entity instances indexed by BaseObjIdentity.
        self.entities_by_identity = {}

        # BaseObjIdentity instances indexed by generator name, so we know which
        # generators have run and what they returned.
        self.identities_by_colletor = {}

    def register_identity(self, identity, components, collector):
        """Build a new entity and associate it with this register."""
        if isinstance(identity, obj.BaseObject):
            identity = obj.BaseObjectIdentity(identity)

        self.register_entity(
            Entity(
                components=components,
                collectors=frozenset([collector]),
                identity=identity,
            )
        )

    def register_entity(self, entity):
        """Register an entity with this register."""
        identity = entity.identity

        if identity in self.entities_by_identity:
            entity = Entity.merge(
                entity,
                self.entities_by_identity[identity],
            )

        self.entities_by_identity[identity] = entity

        for collector in entity.collectors:
            self.identities_by_collector.setdefault(
                collector,
                set(),
            ).add(identity)

    def _collect_entities(self, component, cache_only=False):
        """Find distinct entities that have a particular component.

        Arguments:
            component: The desired component that entities should have.
            cache_only: Only search the cache, don't run collectors.

        Yields:
            Entities that have the desired component.
        """
        collectors = self.session.profile.get_collectors(
            component=component
        )

        results = set()

        for collector in collectors:
            # If we've already run this collector just get the cached output.
            if collector.__name__ in self.identities_by_collector:
                results.update(
                    self.identities_by_collector[collector.__name__]
                )
                continue
            
            if cache_only:
                continue
            
            for identity, components in collector(self.session.profile):
                self.register_identity(
                    identity=identity,
                    components=components,
                    collector=collector.__name__,
                )
                results.add(identity)

        for identity in results:
            yield self.entities_by_identity[identity]
    
    def _retrieve_entities(self, identity):
        """Retrieve entities based on identity.

        Arguments:
            identity: Identity of the entity to retrieve.
                Can be a superposition, in which case more than one entity
                will be yielded.

        Yields:
            The entity that matches identity, if any. If the identity is a
            superposition, more than one entity may be yielded.
        """
        if isinstance(identity, utils.Superposition):
            identities = identity.variants
        elif identity == None:
            identities = []  # Handle None gracefully.
        else:
            identities = [identity]

        for identity in identities:
            if isinstance(identity, obj.BaseObject):
                idx = obj.BaseObjectIdentity(identity)
            else:
                idx = identity

            entity = self.entities_by_identity.get(idx, None)
            if entity:
                yield entity

    def find(self, component=None, identity=None, cache_only=False):
        """Soon to be deprecated in favor of query-based searching.

        Arguments:
            identity: Identity to search for. May be a BaseObject, which is
                automatically converted to a BaseObjectIdentity.

            component: The name of component to search for. Will yield all
                entities that have this component.

            cache_only: Only search the cache. Do not run collectors.
        """
        if identity:
            return self._retrieve_entities(identity)

        if component:
            return self._collect_entities(
                component=component,
                cache_only=False,
            )

        return []

