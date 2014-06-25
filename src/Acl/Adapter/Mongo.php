<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security\Acl\Adapter;

use \Phalcon\Acl\Adapter as PhalconAdapter;
use Phalcon\Acl;
use Phalcon\DI;
use Vegas\Security\Acl\Adapter\Exception\ResourceNotExistsException;
use Vegas\Security\Acl\Adapter\Exception\RoleNotExistsException;
use Vegas\Security\Acl\Role;
use Vegas\Security\Acl\Resource;

/**
 * @use \Phalcon\Acl\Adapter\Mongo
 * @package Vegas\Security\Acl\Adapter
 *
 * Improved \Phalcon\Acl\Adapter\Mongo
 * @see vendor/phalcon/incubator/Library/Phalcon/Acl/Adapter/README.md
 */
class Mongo extends PhalconAdapter implements AdapterInterface
{
    /**
     * @param array $options
     * @throws Exception
     */
    public function __construct($options = array())
    {
        if (empty($options)) {
            $options = array(
                'db'    =>  DI::getDefault()->get('mongo'),
                'roles' =>  'vegas_acl_roles',
                'resources' =>  'vegas_acl_resources',
                'resourcesAccesses' =>  'vegas_acl_resources_accesses',
                'accessList'    =>  'vegas_acl_access_list'
            );
        }
        if (!is_array($options)) {
            throw new Exception("Acl options must be an array");
        }

        if (!isset($options['db'])) {
            throw new Exception("Parameter 'db' is required");
        }

        if (!isset($options['roles'])) {
            throw new Exception("Parameter 'roles' is required");
        }

        if (!isset($options['resources'])) {
            throw new Exception("Parameter 'resources' is required");
        }

        if (!isset($options['resourcesAccesses'])) {
            throw new Exception("Parameter 'resourcesAccesses' is required");
        }

        if (!isset($options['accessList'])) {
            throw new Exception("Parameter 'accessList' is required");
        }

        $this->options = $options;
        $this->_defaultAccess = Acl::DENY;
    }

    /**
     * Returns a mongo collection
     *
     * @param  string $name
     * @return \MongoCollection
     */
    protected function getCollection($name)
    {
        return $this->options['db']->selectCollection($this->options[$name]);
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>$acl->addRole(new Phalcon\Acl\Role('administrator'), 'consultor');</code>
     * <code>$acl->addRole('administrator', 'consultor');</code>
     *
     * @param  string  $role
     * @param  array   $accessInherits
     * @return boolean
     */
    public function addRole($role, $accessInherits = null)
    {
        if (!is_object($role)) {
            $role = new Role($role, '');
        }

        $roles = $this->getCollection('roles');
        $exists = $roles->count(array('name' => $role->getName()));

        if (!$exists) {
            $roles->insert(array(
                'name'        => $role->getName(),
                'description' => $role->getDescription(),
                'removable'   => $role->isRemovable()
            ));

            $this->getCollection('accessList')->insert(array(
                'roles_name'     => $role->getName(),
                'resources_name' => '*',
                'access_name'    => '*',
                'allowed'        => $this->_defaultAccess
            ));
        }

        if ($accessInherits) {
            return $this->addInherit($role->getName(), $accessInherits);
        }

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string  $roleName
     * @return boolean
     */
    public function isRole($roleName)
    {
        return $this->getCollection('roles')->count(array('name' => $roleName)) > 0;
    }

    /**
     * @return \MongoCursor
     */
    public function getRolesWithId() {
        return $this->getCollection('roles')->find();
    }

    /**
     * @param $role
     * @throws Exception\RoleNotExistsException
     * @return array|null
     */
    public function getRole($role)
    {
        if (!isset($role['_id'])) {
            $role = $this->getCollection('roles')->findOne(array('name' => $role));
        }
        if (!$role) {
            throw new RoleNotExistsException();
        }
        $accessList = $this->getRoleAccesses($role['name']);

        $roleObject = new Role($role['name'], $role['description']);
        $roleObject->setRemovable($role['removable']);
        $roleObject->setId($role['_id']);
        $roleObject->setAccessList($accessList);

        return $roleObject;
    }

    /**
     * {@inheritdoc}
     *
     * @return \Vegas\Security\Acl\Role[]
     */
    public function getRoles()
    {
        $roles = array();

        //skip * accesses
        foreach ($this->getCollection('roles')->find() as $row) {
            $roles[] = $this->getRole($row);
        }

        return $roles;
    }


    /**
     * @param $roleName
     * @return \MongoCursor
     */
    public function getRoleAccesses($roleName)
    {
        $accessList = $this->getCollection('accessList')
            ->find(array(
                'roles_name' => $roleName,
                'access_name' => array('$nin' => array('*'))
            ));

        return $accessList;
    }

    /**
     * @param $roleName
     * @return mixed
     */
    public function clearRoleAccesses($roleName)
    {
        return $this->getCollection('accessList')->remove(array('roles_name' => $roleName));
    }

    /**
     * @param $roleName
     * @throws Exception\RoleNotExistsException
     */
    public function dropRole($roleName)
    {
        $role = $this->getRole($roleName);
        if (!$role) {
            throw new RoleNotExistsException();
        }

        //removes role
        $this->getCollection('roles')
            ->remove(array('name' => $role->getName()));

        //removes role accesses
        $this->getCollection('accessList')
            ->remove(array('roles_name' => $role->getName()));
    }

    /**
     * {@inheritdoc}
     *
     * @param  string                 $roleName
     * @param  string                 $roleToInherit
     * @throws \Phalcon\Acl\Exception
     */
    public function addInherit($roleName, $roleToInherit)
    {
        //finds role and role's access list
        $role = $this->getRole($roleName);
        foreach ($role['accessList'] as $accessList) {
            if ($accessList['allowed']) {
                $this->allow($roleName, $accessList['resources_name'], $accessList['access_name']);
            } else {
                $this->deny($role, $accessList['resources_name'], $accessList['access_name']);
            }
        }

        return true;
    }

    /**
     * Removes modules namespace backslashes
     *
     * @param $resourceName
     * @return string
     */
    private function filterResourceName($resourceName)
    {
        return str_replace('\\', '-', $resourceName);
    }

    /**
     * @param $name
     * @return array|null
     * @throws Exception\ResourceNotExistsException
     */
    public function getResource($name)
    {
        $name = $this->filterResourceName($name);
        $resource = $this->getCollection('resources')->findOne(array('name' => $name));
        if (!$resource) {
            throw new ResourceNotExistsException();
        }
        $accesses = $this->getResourceAccesses($resource['name']);
        $resourceObject = new \Vegas\Security\Acl\Resource($resource['name'], $resource['description']);
        $resourceObject->setAccesses($accesses);

        return $resourceObject;
    }

    /**
     * {@inheritdoc}
     *
     * @return \Phalcon\Acl\Resource[]
     */
    public function getResources()
    {
        $resources = array();

        foreach ($this->getCollection('resources')->find() as $row) {
            $resources[] = $this->getResource($row['name']);
        }

        return $resources;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string  $resourceName
     * @return boolean
     */
    public function isResource($resourceName)
    {
        return $this->getCollection('resources')->count(array('name' => $this->filterResourceName($resourceName))) > 0;
    }

    /**
     * @param $resourceName
     * @return array|null
     */
    public function getResourceAccesses($resourceName)
    {
        $accesses = $this->getCollection('resourcesAccesses')
            ->find(array(
                'resources_name' => $this->filterResourceName($resourceName),
                'access_name' => array('$nin' => array('*'))
            )
        );

        return $accesses;
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Add a resource to the the list allowing access to an action
     * $acl->addResource(new \Phalcon\Acl\Resource('customers'), 'search');
     * $acl->addResource('customers', 'search');
     * //Add a resource  with an access list
     * $acl->addResource(new \Phalcon\Acl\Resource('customers'), array('create', 'search'));
     * $acl->addResource('customers', array('create', 'search'));
     * </code>
     *
     * @param  \Phalcon\Acl\Resource $resource
     * @param  array|string          $accessList
     * @return boolean
     */
    public function addResource($resource, $accessList = null)
    {
        if (!is_object($resource)) {
            $resource = new Resource($resource);
        }

        $resources = $this->getCollection('resources');

        $currentResource = $resources->findOne(array('name' => $this->filterResourceName($resource->getName())));
        if (!$currentResource) {
            $resources->insert(array(
                'name'        => $this->filterResourceName($resource->getName()),
                'description' => $resource->getDescription(),
                'scope'       => $resource->getScope()
            ));
        } else {
            $resources->update(array(
                '_id' => $currentResource['_id']
            ), array(
                'name'  =>  $this->filterResourceName($resource->getName()),
                'description'   =>  $resource->getDescription(),
                'scope'       => $resource->getScope()
            ));
        }

        if ($accessList) {
            return $this->addResourceAccess($resource->getName(), $accessList);
        }

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string                 $resourceName
     * @param  array|string           $accessList
     * @return boolean
     * @throws \Phalcon\Acl\Exception
     */
    public function addResourceAccess($resourceName, $accessList)
    {
        if (!$this->isResource($resourceName)) {
            throw new Exception("Resource '" . $resourceName . "' does not exist in ACL");
        }

        $resourcesAccesses = $this->getCollection('resourcesAccesses');

        if (is_array($accessList)) {
            foreach ($accessList as $access) {
                if (!is_array($access)) {
                    $access = array(
                        'name' => $access,
                        'description' => ucfirst($access),
                        'inherit' => ''
                    );
                }
                $exists = $resourcesAccesses->count(array(
                    'resources_name' => $this->filterResourceName($resourceName),
                    'access_name'    => $access['name']
                ));
                if (!$exists) {
                    $resourcesAccesses->insert(array(
                        'resources_name' => $this->filterResourceName($resourceName),
                        'access_name'    => $access['name'],
                        'access_description' => $access['description'],
                        'access_inherit' => isset($access['inherit']) ? $access['inherit'] : ''
                    ));
                }
            }
        } else {
            $exists = $resourcesAccesses->count(array(
                'resources_name' => $this->filterResourceName($resourceName),
                'access_name'    => $accessList
            ));
            if (!$exists) {
                if (!is_array($accessList)) {
                    $accessList = array(
                        'name' => $accessList,
                        'description' => ucfirst($accessList),
                        'inherit' => ''
                    );
                }
                $resourcesAccesses->insert(array(
                    'resources_name' => $this->filterResourceName($resourceName),
                    'access_name'    => $accessList['name'],
                    'access_description' => $accessList['description'],
                    'access_inherit' => $accessList['inherit']
                ));
            }
        }

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @param string       $resourceName
     * @param array|string $accessList
     */
    public function dropResourceAccess($resourceName, $accessList)
    {
        if (is_string($accessList)) {
            $accesses = array($accessList);
        } else {
            $accesses = $accessList;
        }

        foreach ($accesses as $access) {
            $this->getCollection('resourcesAccesses')
                ->remove(array('resources_name' => $this->filterResourceName($resourceName), 'access_name' => $access));
        }
    }

    /**
     * @param $resourceName
     * @throws Exception\ResourceNotExistsException
     */
    public function removeResource($resourceName)
    {
        $resource = $this->getResource($resourceName);
        if (!$resource) {
            throw new ResourceNotExistsException();
        }

        //removes resource
        $this->getCollection('resources')
                        ->remove(array('name' => $resource['name']));

        //removes resource accesses
        $this->getCollection('resourcesAccesses')
                        ->remove(array('resources_name' => $resource['name']));
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Does Andres have access to the customers resource to create?
     * $acl->isAllowed('Andres', 'Products', 'create');
     * //Do guests have access to any resource to edit?
     * $acl->isAllowed('guests', '*', 'edit');
     * </code>
     *
     * @param  string  $role
     * @param  string  $resourceName
     * @param  string  $accessName
     * @return boolean
     */
    public function isAllowed($role, $resourceName, $accessName)
    {
        $resourceName = $this->filterResourceName($resourceName);
        $accessList = $this->getCollection('accessList');
        $access = $accessList->findOne(array(
            '$or' => array(
                array(
                    '$and' => array(
                        array('roles_name' => $role),
                        array('resources_name' => $resourceName),
                        array('access_name' => $accessName)
                    )
                ),
                //is super admin ?
                array(
                    '$and' => array(
                        array('roles_name' => $role),
                        array('resources_name' => 'all')
                    )
                )
            )
        ));
        if (is_array($access)) {
            return (bool) $access['allowed'];
        }

        /**
         * Check the inherited permissions
         */
        $resource = $this->getCollection('resourcesAccesses')->findOne(
            array(
                'resources_name' => $resourceName,
                '$or' => array(
                    array(
                        'access_name' => $accessName
                    ),
                    array(
                        'access_inherit' => array('$in' => array($accessName))
                    )
                )
            )
        );
        if ($resource) {
            $access = $accessList->findOne(array(
                'roles_name' => $role,
                'resources_name' => $resource['resources_name'],
                'access_name' => $resource['access_name']
            ));
            if (is_array($access)) {
                return (bool) $access['allowed'];
            }
        }

        /**
         * Check if there is an common rule for that resource
         */
        $access = $accessList->findOne(array(
            'roles_name'     => $role,
            'resources_name' => $resourceName,
            'access_name'    => '*'
        ));
        if (is_array($access)) {
            return (bool) $access['allowed'];
        }

        return $this->_defaultAccess;
    }

    /**
     * {@inheritdoc}
     * You can use '*' as wildcard
     * Example:
     * <code>
     * //Allow access to guests to search on customers
     * $acl->allow('guests', 'customers', 'search');
     * //Allow access to guests to search or create on customers
     * $acl->allow('guests', 'customers', array('search', 'create'));
     * //Allow access to any role to browse on products
     * $acl->allow('*', 'products', 'browse');
     * //Allow access to any role to browse on any resource
     * $acl->allow('*', '*', 'browse');
     * </code>
     *
     * @param string $roleName
     * @param string $resourceName
     * @param mixed  $access
     */
    public function allow($roleName, $resourceName, $access = '*')
    {
        $accesses = $access;
        if ($access == '*') {
            $accessesCursor = $this->getResourceAccesses($resourceName);
            $accesses = array();
            foreach ($accessesCursor as $item) {
                $accesses[] = $item;
            }
            if (empty($accesses)) $accesses[] = '*';
        }
        $this->allowOrDeny($roleName, $resourceName, $accesses, Acl::ALLOW);
    }

    /**
     * {@inheritdoc}
     * You can use '*' as wildcard
     * Example:
     * <code>
     * //Deny access to guests to search on customers
     * $acl->deny('guests', 'customers', 'search');
     * //Deny access to guests to search or create on customers
     * $acl->deny('guests', 'customers', array('search', 'create'));
     * //Deny access to any role to browse on products
     * $acl->deny('*', 'products', 'browse');
     * //Deny access to any role to browse on any resource
     * $acl->deny('*', '*', 'browse');
     * </code>
     *
     * @param  string  $roleName
     * @param  string  $resourceName
     * @param  mixed   $access
     * @return boolean
     */
    public function deny($roleName, $resourceName, $access = '*')
    {
        $accesses = $access;
        if ($access == '*') {
            $accessesCursor = $this->getResourceAccesses($resourceName);
            $accesses = array();
            foreach ($accessesCursor as $item) {
                $accesses[] = $item;
            }
            if (empty($accesses)) $accesses[] = '*';
        }
        $this->allowOrDeny($roleName, $resourceName, $accesses, Acl::DENY);
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string $roleName
     * @param  string $resourceName
     * @param string $accessDetails
     * @param  integer $action
     * @throws Exception
     * @return boolean
     */
    protected function insertOrUpdateAccess($roleName, $resourceName, $accessDetails, $action)
    {
        $resourceName = $this->filterResourceName($resourceName);
        if (!is_array($accessDetails)) {
            $accessDetails = array(
                'access_name' => $accessDetails,
                'access_inherit' => ''
            );
        }
        /**
         * Check if the access is valid in the resource
         */
        $exists = $this->getCollection('resourcesAccesses')->count(array(
            'resources_name' => $resourceName,
            'access_name'    => $accessDetails['access_name']
        ));
        if (!$exists) {
            throw new Exception(
                "Access '{$accessDetails['access_name']}' does not exist in resource '{$resourceName}' in ACL"
            );
        }

        $accessList = $this->getCollection('accessList');

        $access = $accessList->findOne(array(
            '$and' => array(
                array('roles_name' => $roleName),
                array('resources_name' => $resourceName),
                array(
                    '$or' => array(
                        array('access_name' => $accessDetails['access_name']),
                        array('inherit' => $accessDetails['access_name'])
                    )
                )
            )
        ));
        if (!$access) {
            $accessList->insert(array(
                'roles_name'     => $roleName,
                'resources_name' => $resourceName,
                'access_name'    => $accessDetails['access_name'],
                'inherit'        => $accessDetails['access_inherit'],
                'allowed'        => $action
            ));
        } else {
            $access['allowed'] = $action;
            $accessList->save($access);
        }

        /**
         * Update the access '*' in access_list
         */
        $exists = $accessList->count(array(
            'roles_name'     => $roleName,
            'resources_name' => $resourceName,
            'access_name'    => '*'
        ));
        if (!$exists) {
            $accessList->insert(array(
                'roles_name'     => $roleName,
                'resources_name' => $resourceName,
                'access_name'    => '*',
                'allowed'        => $this->_defaultAccess
            ));
        }

        return true;
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string $roleName
     * @param  string $resourceName
     * @param  string $accesses
     * @param  integer $action
     * @throws Exception
     */
    protected function allowOrDeny($roleName, $resourceName, $accesses, $action)
    {

        if (!$this->isRole($roleName)) {
            throw new Exception('Role "' . $roleName . '" does not exist in the list');
        }
        if (is_array($accesses)) {
            foreach ($accesses as $access) {
                $this->insertOrUpdateAccess($roleName, $resourceName, $access, $action);
            }
        } else {
            $this->insertOrUpdateAccess($roleName, $resourceName, $accesses, $action);
        }
    }

    /**
     * @return mixed
     */
    public function removeResources()
    {
        return $this->getCollection('resources')->remove(array());
    }

    /**
     * @return mixed
     */
    public function removeResourceAccesses()
    {
        return $this->getCollection('resourcesAccesses')->remove(array());
    }
}
 
