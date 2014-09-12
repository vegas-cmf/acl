<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Tests\Acl\Adapter;

use Phalcon\Acl;
use Phalcon\DI;
use Vegas\Security\Acl\Adapter\Mongo;

class MongoTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Vegas\Security\Acl
     */
    protected $acl;

    /**
     * @var \Vegas\Security\Acl\Adapter\Mongo
     */
    protected $adapter;
    
    /**
     * Clear all ACL settings before starting tests.
     */
    public static function setUpBeforeClass()
    {
        $mongo = DI::getDefault()->get('mongo');
        $mongo->selectCollection('vegas_acl_roles')->remove();
        $mongo->selectCollection('vegas_acl_resources')->remove();
        $mongo->selectCollection('vegas_acl_access_list')->remove();
        $mongo->selectCollection('vegas_acl_resources_accesses')->remove();
    }
    
    public function setUp()
    {
        $this->acl = DI::getDefault()->get('acl');
        $this->adapter = new Mongo;
    }

    public function tearDown()
    {
        $this->adapter = null;
    }

    public function testConstructEndsWithExceptionProvider()
    {
        return [
            // #0
            [
                'someString',
                'Acl options must be an array'
            ],
            // #1
            [
                123,
                'Acl options must be an array'
            ],
            // #2
            [
                true,
                'Acl options must be an array'
            ],
            // #3
            [
                (new \StdClass()),
                'Acl options must be an array'
            ],
            // #4
            [
                [
                    'noDbParameter' => 'foo',
                ],
                'Parameter \'db\' is required'
            ],
            // #5
            [
                [
                    'db' => 'foo',
                    'noRolesParameter' => 'foo',
                ],
                'Parameter \'roles\' is required'
            ],
            // #6
            [
                [
                    'db' => 'foo',
                    'roles' => 'foo',
                    'noResourcesParameter' => 'foo',
                ],
                'Parameter \'resources\' is required'
            ],
            // #7
            [
                [
                    'db' => 'foo',
                    'roles' => 'foo',
                    'resources' => 'foo',
                ],
                'Parameter \'resourcesAccesses\' is required'
            ],
            // #8
            [
                [
                    'db' => 'foo',
                    'roles' => 'foo',
                    'resources' => 'foo',
                    'resourcesAccesses' => 'foo',
                ],
                'Parameter \'accessList\' is required'
            ],
        ];
    }

    /**
     * @dataProvider testConstructEndsWithExceptionProvider
     * @param mixed $options
     * @param string $exceptionMessage
     */
    public function testConstructEndsWithException($options, $exceptionMessage)
    {
        $this->setExpectedException('Exception', $exceptionMessage);
        new Mongo($options);
    }

    public function testValidConfiguration()
    {
        $options = [
                'db'    =>  DI::getDefault()->get('mongo'),
                'roles' => 'vegas_acl_roles',
                'resources' => 'vegas_acl_resources',
                'resourcesAccesses' => 'vegas_acl_resources_accesses',
                'accessList' => 'vegas_acl_access_list'
            ];
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mongo', new Mongo());
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mongo', new Mongo($options));
    }

    public function testInvalidConfiguration()
    {
        try {
            new Mongo(new \stdClass);
            $this->fail('Exception not triggered');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Exception', $e);
        }

        $options = [
                'db'    =>  DI::getDefault()->get('mongo'),
                'roles' => 'vegas_acl_roles',
                'resources' => 'vegas_acl_resources',
                'resourcesAccesses' => 'vegas_acl_resources_accesses',
                'accessList' => 'vegas_acl_access_list'
            ];
        foreach ($options as $key => $val) {
            $invalidOptions = $options;
            unset($invalidOptions[$key]);
            try {
                new Mongo($invalidOptions);
                $this->fail('Exception not triggered');
            } catch (\Exception $e) {
                $this->assertInstanceOf('\Vegas\Security\Acl\Exception', $e);
            }
        }
    }

    public function testCreateRoleWithAccessPermissions()
    {
        $this->acl->getRoleManager()->add('Editor', 'Content editor');
        $this->acl->getResourceManager()->add('mvc:wiki:Frontend\Handbook', "Wiki hand books", array("index", "edit", "add", "delete"));
        $this->acl->getResourceManager()->add('mvc:wiki:Frontend\Articles', "Wiki articles", array("index", "add"));

        $this->assertCount(1, array_filter($this->acl->getRoles(), function($role) {
            return $role->getName() === 'Editor';
        }));
        $this->assertCount(2, array_filter($this->acl->getResourceManager()->getResources(), function($resource) {
            return in_array($resource->getName(), ['mvc:wiki:Frontend-Handbook', 'mvc:wiki:Frontend-Articles']);
        }));
    }

    /**
     * @depends testCreateRoleWithAccessPermissions
     */
    public function testPermissions()
    {
        $acl = $this->acl;

        $roleManager = $acl->getRoleManager();
        $resourceManager = $acl->getResourceManager();

        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', ['delete']);
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'add'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'delete'));

        $acl->allow('Editor', 'mvc:wiki:Frontend\Handbook', 'delete');
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'delete'));

        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', 'delete');
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'delete'));

        $resourceManager->add('menu:wiki:Frontend\Wiki', "Menu Wiki", 'show');
        $acl->deny('Editor', 'menu:wiki:Frontend\Wiki', 'show');
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'menu:wiki:Frontend\Wiki', 'show'));

        $resourceManager->add('mvc:wiki:Frontend\Handbook', 'Wiki hand book', array(
            array(
                'name' => 'test',
                'description' => 'test action',
                'inherit' => 'delete'
            )
        ));
        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', ['delete']);
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Wiki', 'delete'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Wiki', 'test'));

        $roleManager->add('SuperAdmin', 'Super hero');
        $resourceManager->add('all', 'All and all', ['*']);
        $acl->allow('SuperAdmin', 'all', '*');

        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('SuperAdmin', 'mvc:wiki:Frontend\Wiki', 'delete'));
    }

    public function testAddRoleIfRoleIsNotObject()
    {
        $this->clearRoleManagerRoles();

        $newRoles = ['fooBarBaz', 'Qwerty'];
        foreach ($newRoles as $name) {
            $this->adapter->addRole($name);
        }

        $mongoRoles = $this->adapter->getRoles();
        $newRolesCount = count($newRoles);
        $newRolesMaxItemIndex = $newRolesCount - 1;

        $this->assertCount($newRolesCount, $mongoRoles);
        $this->assertArrayHasKey($newRolesMaxItemIndex, $mongoRoles);

        foreach ($mongoRoles as $index => $role) {
            $this->assertSame($newRoles[$index], (string)$role);
        }
    }

    public function testAddRoleWithAccessInherits()
    {
        $this->clearRoleManagerRoles();

        $this->adapter->addRole('inheritRole');
        $role = $this->adapter->getRole('inheritRole');

        $accessList = [
            [
                'access_name' => 'mvc:foo:Bar',
                'resources_name' => 'mvcFooBar',
            ],
            [
                'access_name' => 'mvc:baz:Sna-Fu',
                'resources_name' => 'mvcBazSnaFu',
            ],
        ];

        $role->setAccessList($accessList);
        $this->assertCount(2, $role->getAccessList());

        $this->adapter->addRole('fooInheritanceRole', 'inheritRole');
        $this->adapter->addRole('NotExistingRoleInheritance');
        $this->assertCount(3, $this->adapter->getRoles());
    }

    public function testAddInherit()
    {
        $roleName = 'roleFoo111';
        $inheritName = 'INheritFooBAz';

        $this->acl->getResourceManager()->add('mvc:foo:Resource\One', "Res one", array("index", "update"));
        $this->acl->getResourceManager()->add('mvc:bar:Resource\Two', "Res two", array("delete", "read"));

        $this->adapter->addRole($roleName);
        $this->adapter->addRole($inheritName);

        $inheritRole = $this->adapter->getRole($inheritName);

        $accessList = [
            [
                'resources_name' => 'mvc:foo:Resource\One',
                'access_name' => 'index',
            ],
            [
                'resources_name' => 'mvc:foo:Resource\One',
                'access_name' => 'update',
            ],
            [
                'resources_name' => 'mvc:bar:Resource\Two',
                'access_name' => 'read',
            ],
            [
                'resources_name' => 'mvc:bar:Resource\Two',
                'access_name' => 'delete',
            ],
        ];

        $inheritRole->setAccessList($accessList);
        $this->assertCount(2, $inheritRole->getAccessList());

        $this->adapter->addInherit($roleName, $inheritRole);

        $this->assertCount(4, $this->adapter->getRoleAccesses($roleName));
    }

    public function testGetRolesWithId()
    {
        $this->clearRoleManagerRoles();

        $result = $this->adapter->getRolesWithId();
        $this->assertInstanceOf('MongoCursor', $result);
        $this->assertCount(0, $result);

        $this->adapter->addRole('fooRole');
        $this->adapter->addRole('barRole');
        $this->adapter->addRole('bazRole');
        $this->assertCount(3, $result);

    }

    public function testClearRoleAccesses()
    {
        $roleName = 'newRoleAccessFoo';
        $collectionName = $this->adapter->options['accessList'];
        $accessList = $this->adapter->options['db']->selectCollection($collectionName);

        $accessList->save([
            'roles_name'     => $roleName,
            'resources_name' => 'res',
            'access_name'    => 'access',
            'inherit'        => 'inherit',
            'allowed'        => 1
        ]);

        $this->assertCount(1, $this->adapter->getRoleAccesses($roleName));

        $this->adapter->clearRoleAccesses($roleName);

        $this->assertCount(0, $this->adapter->getRoleAccesses($roleName));
    }

    public function testGetResourceThrowsException()
    {
        $resourceName = 'NotExistingResource';
        $exceptionMessage = 'Resource \''. $resourceName .'\' does not exist';
        $this->setExpectedException('\Vegas\Security\Acl\Adapter\Exception\ResourceNotExistsException', $exceptionMessage);
        $this->adapter->getResource($resourceName);
    }

    public function testAddResourceWithNewObjectCreation()
    {
        $resourceName = 'NewResourceNameBar';
        $result = $this->adapter->addResource($resourceName);

        $this->assertTrue($result);
        $this->assertInstanceOf('\Vegas\Security\Acl\Resource', $this->adapter->getResource($resourceName));
    }

    public function testRemoveResource()
    {
        $resourceName = 'AResourceNameTest';
        $result = $this->adapter->addResource($resourceName);

        $this->assertTrue($result);
        $this->assertInstanceOf('\Vegas\Security\Acl\Resource', $this->adapter->getResource($resourceName));

        $this->adapter->removeResource($resourceName);
        $exceptionMessage = 'Resource \''. $resourceName .'\' does not exist';
        $this->setExpectedException('\Vegas\Security\Acl\Adapter\Exception\ResourceNotExistsException', $exceptionMessage);
        $this->adapter->getResource($resourceName);
    }

    public function testGetValidatedAccessesThrowsRoleException()
    {
        $roleName = 'NotExistingRoleName';
        $exceptionMessage = 'Role \''. $roleName .'\' does not exist';

        $this->setExpectedException('\Vegas\Security\Acl\Adapter\Exception\RoleDoesNotExistException', $exceptionMessage);
        $this->adapter->allow($roleName, 'madeUpResourceName', 'access');
    }

    public function testGetValidatedAccessesThrowsResourceException()
    {
        $roleName = 'existingRole';
        $resourceName = 'madeUpResourceName';
        $exceptionMessage = 'Resource \''. $resourceName .'\' does not exist';

        $this->adapter->addRole($roleName);
        $this->setExpectedException('\Vegas\Security\Acl\Adapter\Exception\ResourceNotExistsException', $exceptionMessage);

        $this->adapter->allow($roleName, $resourceName, 'access');
    }

    public function testGetValidatedAccessesThrowsCreationAccessExceptionProvider()
    {
        return [
            [
                'testRoleOne',
                'all',
                'NotWildcardAccess',
            ],
            [
                'testRoleTwo',
                'notWildcardResource',
                '*',
            ],
        ];
    }

    /**
     * @dataProvider testGetValidatedAccessesThrowsCreationAccessExceptionProvider
     * @param string        $roleName
     * @param string        $resourceName
     * @param string|array $access
     */
    public function testGetValidatedAccessesThrowsCreationAccessException($roleName, $resourceName, $access)
    {
        $exceptionMessage = 'Cannot create access to \''. $access .'\' in \''. $resourceName .'\' for role ' . $roleName;

        $this->adapter->addRole($roleName);
        $this->adapter->addResource($resourceName);
        $this->setExpectedException('\Exception', $exceptionMessage);

        $this->adapter->allow($roleName, $resourceName, $access);
    }

    public function testInsertOrUpdateThrowsAccessException()
    {
        $roleName = 'roleQwe';
        $resourceName = 'resourceAsd';
        $accessName = 'accessZxc';

        $this->adapter->addRole($roleName);
        $this->adapter->addResource($resourceName);

        $exceptionMessage = 'Access \'' . $accessName . '\' does not exist in resource \'' . $resourceName . '\' in ACL';
        $this->setExpectedException('\Vegas\Security\Acl\Adapter\Exception\ResourceAccessNotExistsException', $exceptionMessage);
        $this->adapter->allow($roleName, $resourceName, $accessName);
    }

    public function testInsertOrUpdateSavesAllowedIfNotSet()
    {
        $roleName = 'role234Foo';
        $resourceName = 'resourceBaz154';
        $accessName = 'accessBazName';
        $roleAccessList = [
            [
                'resources_name' => 'mvc:foo:Resource\One',
                'access_name' => 'index',
            ],
            [
                'resources_name' => 'mvc:foo:Resource\One',
                'access_name' => 'update',
            ],
        ];

        $resourceAccessList = [
            [
                'name' => $accessName,
                'description' => 'desc',
                'resources_name' => 'mvc:foo:Baz\Foo-Bar',
                'access_name' => 'index',
            ],
        ];

        $aclParams = [
            'roles_name'     => $roleName,
            'resources_name' => $resourceName,
            'access_name'    => $accessName,
        ];

        $this->adapter->addRole($roleName);
        $role = $this->adapter->getRole($roleName);
        $role->setAccessList($roleAccessList);

        $collectionName = $this->adapter->options['accessList'];
        $accessList = $this->adapter->options['db']->selectCollection($collectionName);
        $accessList->save($aclParams);

        $acl = $accessList->findOne($aclParams);
        $this->assertNotNull($acl);
        $this->assertFalse(isset($acl['allowed']));

        $this->adapter->addResource($resourceName);
        $this->adapter->addResourceAccess($resourceName, $resourceAccessList);

        $this->adapter->allow($roleName, $resourceName, $accessName);
        $acl = $accessList->findOne($aclParams);
        $this->assertSame(1, $acl['allowed']);
    }

    public function testRemoveResources()
    {
        $resourceName = 'ResFooTest';
        $resourceDescription = 'ResDescriptionBaz';
        $collectionName = $this->adapter->options['resources'];
        $resourcesList = $this->adapter->options['db']->selectCollection($collectionName);
        $resourceParams = [
            'name' => $resourceName,
            'description' => $resourceDescription,
        ];

        $this->acl->getResourceManager()->add($resourceName, $resourceDescription);

        $resource = $resourcesList->find($resourceParams);
        $this->assertNotNull($resource);

        $this->adapter->removeResources();

        $resource = $resourcesList->find($resourceParams);
        $this->assertCount(0, $resource);
    }

    public function testRemoveResourceAccesses()
    {
        $resourceName = 'ResourceTestNameF';
        $resourceDescription = 'ResourceTestDescription..';
        $accessList = [
            [
                'name' => 'resAclNameTest',
                'description' => 'fooNameTestDesc',
                'resources_name' => 'mvc:test:Foo\Res-Method',
                'access_name' => 'delete',
            ],
            [
                'name' => 'resAclNameTestTwo',
                'description' => 'resAclNameTestTwoDesc',
                'resources_name' => 'mvc:test:Foo\Res-Method',
                'access_name' => 'index',
            ],
        ];

        $this->acl->getResourceManager()->add($resourceName, $resourceDescription, $accessList);

        $accesses = $this->adapter->getResourceAccesses($resourceName);
        $this->assertNotNull($accesses);

        $this->adapter->removeResourceAccesses($resourceName);

        $accesses = $this->adapter->getResourceAccesses($resourceName);
        $this->assertCount(0, $accesses);
    }

    private function clearRoleManagerRoles()
    {
        $roleManager = $this->acl->getRoleManager();

        foreach ($roleManager->getRoles() as $name) {
            $roleManager->dropRole((string)$name);
        }
    }
}
