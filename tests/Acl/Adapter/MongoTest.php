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
    }

//    public function testConstructEndsWithExceptionProvider()
//    {
//        return [
//            // #0
//            [
//                'someString',
//                'Acl options must be an array'
//            ],
//            // #1
//            [
//                123,
//                'Acl options must be an array'
//            ],
//            // #2
//            [
//                true,
//                'Acl options must be an array'
//            ],
//            // #3
//            [
//                (new \StdClass()),
//                'Acl options must be an array'
//            ],
//            // #4
//            [
//                [
//                    'noDbParameter' => 'foo',
//                ],
//                'Parameter \'db\' is required'
//            ],
//            // #5
//            [
//                [
//                    'db' => 'foo',
//                    'noRolesParameter' => 'foo',
//                ],
//                'Parameter \'roles\' is required'
//            ],
//            // #6
//            [
//                [
//                    'db' => 'foo',
//                    'roles' => 'foo',
//                    'noResourcesParameter' => 'foo',
//                ],
//                'Parameter \'resources\' is required'
//            ],
//            // #7
//            [
//                [
//                    'db' => 'foo',
//                    'roles' => 'foo',
//                    'resources' => 'foo',
//                ],
//                'Parameter \'resourcesAccesses\' is required'
//            ],
//            // #8
//            [
//                [
//                    'db' => 'foo',
//                    'roles' => 'foo',
//                    'resources' => 'foo',
//                    'resourcesAccesses' => 'foo',
//                ],
//                'Parameter \'accessList\' is required'
//            ],
//        ];
//    }
//
//    /**
//     * @dataProvider testConstructEndsWithExceptionProvider
//     * @param mixed $options
//     * @param string $exceptionMessage
//     */
//    public function testConstructEndsWithException($options, $exceptionMessage)
//    {
//        $this->setExpectedException('Exception', $exceptionMessage);
//        new Mongo($options, 1);
//    }
//
//    public function testValidConfiguration()
//    {
//        $options = [
//                'db'    =>  DI::getDefault()->get('mongo'),
//                'roles' => 'vegas_acl_roles',
//                'resources' => 'vegas_acl_resources',
//                'resourcesAccesses' => 'vegas_acl_resources_accesses',
//                'accessList' => 'vegas_acl_access_list'
//            ];
//        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mongo', new Mongo());
//        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mongo', new Mongo($options));
//    }
//
//    public function testInvalidConfiguration()
//    {
//        try {
//            new Mongo(new \stdClass);
//            $this->fail('Exception not triggered');
//        } catch (\Exception $e) {
//            $this->assertInstanceOf('\Vegas\Security\Acl\Exception', $e);
//        }
//
//        $options = [
//                'db'    =>  DI::getDefault()->get('mongo'),
//                'roles' => 'vegas_acl_roles',
//                'resources' => 'vegas_acl_resources',
//                'resourcesAccesses' => 'vegas_acl_resources_accesses',
//                'accessList' => 'vegas_acl_access_list'
//            ];
//        foreach ($options as $key => $val) {
//            $invalidOptions = $options;
//            unset($invalidOptions[$key]);
//            try {
//                new Mongo($invalidOptions);
//                $this->fail('Exception not triggered');
//            } catch (\Exception $e) {
//                $this->assertInstanceOf('\Vegas\Security\Acl\Exception', $e);
//            }
//        }
//    }
//
//    public function testCreateRoleWithAccessPermissions()
//    {
//        $this->acl->getRoleManager()->add('Editor', 'Content editor');
//        $this->acl->getResourceManager()->add('mvc:wiki:Frontend\Handbook', "Wiki hand books", array("index", "edit", "add", "delete"));
//        $this->acl->getResourceManager()->add('mvc:wiki:Frontend\Articles', "Wiki articles", array("index", "add"));
//
//        $this->assertCount(1, array_filter($this->acl->getRoles(), function($role) {
//            return $role->getName() === 'Editor';
//        }));
//        $this->assertCount(2, array_filter($this->acl->getResourceManager()->getResources(), function($resource) {
//            return in_array($resource->getName(), ['mvc:wiki:Frontend-Handbook', 'mvc:wiki:Frontend-Articles']);
//        }));
//    }
//
//    /**
//     * @depends testCreateRoleWithAccessPermissions
//     */
//    public function testPermissions()
//    {
//        $acl = $this->acl;
//
//        $roleManager = $acl->getRoleManager();
//        $resourceManager = $acl->getResourceManager();
//
//        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', ['delete']);
//        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'add'));
//        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'delete'));
//
//        $acl->allow('Editor', 'mvc:wiki:Frontend\Handbook', 'delete');
//        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'delete'));
//
//        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', 'delete');
//        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Handbook', 'delete'));
//
//        $resourceManager->add('menu:wiki:Frontend\Wiki', "Menu Wiki", 'show');
//        $acl->deny('Editor', 'menu:wiki:Frontend\Wiki', 'show');
//        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'menu:wiki:Frontend\Wiki', 'show'));
//
//        $resourceManager->add('mvc:wiki:Frontend\Handbook', 'Wiki hand book', array(
//            array(
//                'name' => 'test',
//                'description' => 'test action',
//                'inherit' => 'delete'
//            )
//        ));
//        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', ['delete']);
//        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Wiki', 'delete'));
//        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Wiki', 'test'));
//
//        $roleManager->add('SuperAdmin', 'Super hero');
//        $resourceManager->add('all', 'All and all', ['*']);
//        $acl->allow('SuperAdmin', 'all', '*');
//
//        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('SuperAdmin', 'mvc:wiki:Frontend\Wiki', 'delete'));
//    }
//
//    public function testAddRoleIfRoleIsNotObject()
//    {
//        $this->clearRoleManagerRoles();
//        $mongo = new Mongo();
//
//        $newRoles = ['fooBarBaz', 'Qwerty'];
//        foreach ($newRoles as $name) {
//            $mongo->addRole($name);
//        }
//
//        $mongoRoles = $mongo->getRoles();
//        $newRolesCount = count($newRoles);
//        $newRolesMaxItemIndex = $newRolesCount - 1;
//
//        $this->assertCount($newRolesCount, $mongoRoles);
//        $this->assertArrayHasKey($newRolesMaxItemIndex, $mongoRoles);
//
//        foreach ($mongoRoles as $index => $role) {
//            $this->assertSame($newRoles[$index], (string)$role);
//        }
//    }
//
//    public function testAddRoleWithAccessInherits()
//    {
//        $this->clearRoleManagerRoles();
//        $mongo = new Mongo();
//
//        $mongo->addRole('inheritRole');
//        $role = $mongo->getRole('inheritRole');
//
//        $accessList = [
//            [
//                'access_name' => 'mvc:foo:Bar',
//                'resources_name' => 'mvcFooBar',
//            ],
//            [
//                'access_name' => 'mvc:baz:Sna-Fu',
//                'resources_name' => 'mvcBazSnaFu',
//            ],
//        ];
//
//        $role->setAccessList($accessList);
//        $this->assertCount(2, $role->getAccessList());
//
//        $mongo->addRole('fooInheritanceRole', 'inheritRole');
//        $mongo->addRole('NotExistingRoleInheritance');
//        $this->assertCount(3, $mongo->getRoles());
//    }
//
//    public function testGetRolesWithId()
//    {
//        $this->clearRoleManagerRoles();
//        $mongo = new Mongo();
//
//        $result = $mongo->getRolesWithId();
//        $this->assertInstanceOf('MongoCursor', $result);
//        $this->assertCount(0, $result);
//
//        $mongo->addRole('fooRole');
//        $mongo->addRole('barRole');
//        $mongo->addRole('bazRole');
//        $this->assertCount(3, $result);
//
//    }

    public function testClearRoleAccesses()
    {
        $this->clearRoleManagerRoles();
        $mongo = new Mongo();
        $roleName = 'newRoleAccessFoo';
        $resourceName = 'mvc:role:Foo\Bar';

        $mongo->addRole($roleName);
        $role = $mongo->getRole($roleName);

        $resourceManager = $this->acl->getResourceManager();

        $resourceManager->add($resourceName, 'Desc', ['methodOne', 'methodTwo']);
        var_dump(1, $mongo->getResourceAccesses($resourceName));die;

//        $accessList = [
//            [
//                'access_name' => 'mvc:foo:Bar',
//                'resources_name' => 'mvcFooBar',
//            ],
//            [
//                'access_name' => 'mvc:baz:Sna-Fu',
//                'resources_name' => 'mvcBazSnaFu',
//            ],
//        ];
//
//        $role->setAccessList($accessList);
//        $this->assertCount(2, $role->getAccessList());
//
//        $mongo->clearRoleAccesses($roleName, 1);
//        var_dump($roleName, $role->getAccessList());die;
//        $this->assertCount(0, $role->getAccessList());
    }

    private function clearRoleManagerRoles()
    {
        $roleManager = $this->acl->getRoleManager();

        foreach ($roleManager->getRoles() as $name) {
            $roleManager->dropRole((string)$name);
        }
    }
}
