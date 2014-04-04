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


class EntityCache(object):
    """Per-session register of entities."""

    def __init__(self, session):
        # Entity instances indexed by BaseObjIdentity.
        self.entities_by_identity = {}

        # BaseObjIdentity instances indexed by generator name, so we know which
        # generators have run and what they returned.
        self.identities_by_generator = {}
        self.session = session

    def register_entity(self, entity, generator):
        """Associate entity with this register."""
        entity.session = self.session
        entity.generators = set([generator])

        identity = entity.identity
        if identity in self.entities_by_identity:
            entity = Entity.merge(
                entity,
                self.entities_by_identity[identity]
            )

        self.entities_by_identity[identity] = entity
        self.identities_by_generator.setdefault(
            generator,
            set()).add(identity)

    def _generate_entities(self, entity_cls, include_subclasses=True,
                           cache_only=False):
        """Find distinct entities of a particular type.

        Arguments:
          include_subclasses (default: True): Also look for subclasses.

          entity_cls: The desired class of entities.

          cache_only: Only search the cache, don't run generators.

        Yields:
          Entities of class entity_cls (or subclass. Entities are merged
          using Entity.merge if two or more are found to represent the
          same key object.
        """
        generators = self.session.profile.entity_generators(
            entity_cls=entity_cls,
            subclasses=include_subclasses,
        )

        results = set()

        for generator in generators:
            # If we've already run this generator just get the cached output.
            if generator.__name__ in self.identities_by_generator:
                results.update(
                    self.identities_by_generator[generator.__name__]
                )
                continue

            # Skip ahead if we're only hitting cache.
            if cache_only:
                continue

            # Otherwise register the entities from the generator.
            for entity in generator(self.session.profile):
                self.register_entity(entity, generator.__name__)
                results.add(entity.identity)

        # Generators can return more than one type of entity, which is why the
        # filtering by isinstance is necessary to ensure we return correct
        # results.
        for identity in results:
            entity = self.entities_by_identity[identity]
            if isinstance(entity, entity_cls):
                yield entity

    def _retrieve_entities(self, entity_cls, key_obj, cache_only=False):
        """Given a key object, find entities that represent it.

        If the entity already exists in cache it will be retrieved. Otherwise,
        it'll be creared using entity_cls as class and "Session" as generator
        name.

        If key_obj is a superposition (from merge) then more than one entity
        will be yielded.

        Yields:
          An instance of Entity, most likely entity_cls. If the key object
          is a superposition, more than one result will be yielded.

        Arguments:
          entity_cls: The expected class of the entity. Not guaranteed.

          key_obj: The key object to look up. Can be any object that implements
            obj_offset, obj_vm and obj_type, such as BaseObjectIdentity. Can
            also be a superposition of more values.
        """
        if isinstance(key_obj, utils.Superposition):
            key_objs = key_obj.variants
        elif key_obj == None:
            key_objs = []  # Handle None gracefully.
        else:
            key_objs = [key_obj]

        for key_obj in key_objs:
            # We coerce the key object into a type suitable for use as a
            # dict key.
            idx = obj.BaseObjectIdentity(base_obj=key_obj)

            if idx in self.entities_by_identity:
                yield self.entities_by_identity[idx]
            elif not cache_only:
                entity = entity_cls(key_obj=key_obj, session=self)
                self.register_entity(entity, generator="Session")
                yield entity

    def find(self, entity_cls=None, key_obj=None,
             include_subclasses=True, cache_only=False):
        """Find and yield entities based on class or key object.

        If key_obj is given, will yield entity to represent that object. If
        one doesn't exist it will be created with "Session" as generator and
        entity_cls as class.

        If key_obj is a superposition all matches will be yielded as outlined
        above.

        If only entity_cls is given will yield all objects of that class,
        running generators as appropriate.

        Arguments:
          key_obj: Key object to search for. Can also be any object that
            implements obj_vm, obj_offset and obj_type, such as
            BaseObjectIdentity. Superposition is supported (see
            utils.Superposition).

          entity_cls: Entity class to search for.

          include_subclasses (default: True): If searching for all entities
            of class, also include subclasses.

          cache_only (default: False): Only search the cache, do not create
            new entities or run generators.

        Returns:
          Iterable of instances of Entity, possibly of entity_cls.
        """
        if key_obj:
            return self._retrieve_entities(
                key_obj=key_obj,
                entity_cls=entity_cls,
                cache_only=cache_only,
            )

        if entity_cls:
            return self._generate_entities(
                entity_cls=entity_cls,
                cache_only=cache_only,
                include_subclasses=include_subclasses,
            )

        return []


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

