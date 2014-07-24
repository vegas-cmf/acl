<?php
/**
 * This file is part of Vegas package
 *
 * @author Radosław Fąfara <radek@archdevil.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Tests\Acl\Adapter;

use Phalcon\Acl;
use Phalcon\DI;
use Vegas\Security\Acl\Adapter\Mysql;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclRole;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclResource;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess;
use Vegas\Security\Acl\Resource;

class MysqlTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Vegas\Security\Acl
     */
    protected $acl;
    
    /**
     * @var \Vegas\Security\Acl\Adapter\Mysql
     */
    protected $adapter;
    
    /**
     * Clear all ACL settings before starting tests.
     */
    public static function setUpBeforeClass()
    {        
        foreach (AclResource::find() as $resource) {
            $resource->delete();
        }
        foreach (AclRole::find() as $role) {
            $role->delete();
        }
        $resource = new AclResource;
        $resource->create([
            'name'          => Resource::WILDCARD,
            'description'   => 'All in all (built-in)',
        ]);
        (new AclResourceAccess)->create([
            'name'            => Resource::ACCESS_WILDCARD,
            'description'     => 'All in all (built-in)',
            'acl_resource_id' => $resource->id
        ]);
    }
    
    public function setUp()
    {
        $this->acl = DI::getDefault()->get('acl_mysql');
        $this->adapter = $this->acl->getAdapter();
    }
    
    public function testValidConfiguration()
    {
        $options = [
                'roles'             =>  'vegas_acl_roles',
                'resources'         =>  'vegas_acl_resources',
                'resourcesAccesses' =>  'vegas_acl_resources_accesses',
                'accessList'        =>  'vegas_acl_access_list'
            ];
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mysql', $this->adapter);
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mysql', new Mysql());
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mysql', new Mysql($options));
    }
    
    public function testInvalidConfiguration()
    {
        try {
            new Mysql(new \stdClass);
            $this->fail('Exception not triggered');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Exception', $e);
        }
        
        $options = [
                'roles'             =>  'vegas_acl_roles',
                'resources'         =>  'vegas_acl_resources',
                'resourcesAccesses' =>  'vegas_acl_resources_accesses',
                'accessList'        =>  'vegas_acl_access_list'
            ];
        foreach ($options as $key => $val) {
            $invalidOptions = $options;
            unset($invalidOptions[$key]);
            try {
                new Mysql($invalidOptions);
                $this->fail('Exception not triggered');
            } catch (\Exception $e) {
                $this->assertInstanceOf('\Vegas\Security\Acl\Exception', $e);
            }
        }
    }
    
    public function testAddRoleUsingName()
    {
        $name = 'TestRole';
        
        $this->assertFalse($this->adapter->isRole($name));
        $result = $this->adapter->addRole($name);
        
        $this->assertTrue($result);
        $this->assertTrue($this->adapter->isRole($name));
    }
    
    public function testAddResourceUsingName()
    {
        $name = 'TestResource';
        
        $this->assertFalse($this->adapter->isResource($name));
        $result = $this->adapter->addResource($name);
        $this->assertTrue($result);
        
        $this->assertInstanceOf('\Vegas\Security\Acl\Resource', $this->adapter->getResource($name));
    }
    
    /**
     * @depends testAddResourceUsingName
     */
    public function testAddRoleWithAllowedResources()
    {
        $name = 'TestRoleWithResources';
        $allowedActions = ['index', 'edit'];
        
        $this->adapter->addRole($name);
        
        $resourceName = 'TestResource';
        $return = $this->adapter->addResourceAccess($resourceName, $allowedActions);
        $this->assertTrue($return);
        
        $this->adapter->deny($name, $resourceName, 'index');
        $this->adapter->allow($name, $resourceName, $allowedActions);
    }
    
    /**
     * @depends testAddRoleWithAllowedResources
     */
    public function testAddInheritedRoleUsingName()
    {
        $name = 'InheritedTestRole';
        $inherited = 'TestRoleWithResources';        
        
        $this->assertTrue($this->adapter->isRole($inherited));
        $this->assertFalse($this->adapter->isRole($name));
        $result = $this->adapter->addRole($name, $inherited);
        
        $this->assertTrue($result);
    }
    
    public function testCannotAddAccessToNonExistingResource()
    {
        $name = 'NonExistingResource';
        
        try {
            $this->adapter->addResourceAccess($name, ['index', 'edit']);
            $this->fail('Exception not triggered');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Exception', $e);
        }
    }
    
    public function testRemoveRoleUsingName()
    {
        $name = 'RoleToRemove';
        
        $this->adapter->addRole($name);
        $this->assertTrue($this->adapter->isRole($name));
        
        $this->adapter->dropRole($name);
        $this->assertFalse($this->adapter->isRole($name));
    }
    
    public function testRemoveAllResourceAccesses()
    {
        $name = 'mvc:docs:Frontend\Removable';
        
        $this->adapter->addResource($name);
        $this->adapter->addResourceAccess($name, ['add', 'edit', 'remove']);
        $resource = $this->adapter->getResource($name);
        
        $this->assertCount(3, $resource->getAccesses());
        
        $this->adapter->removeResourceAccesses();
        
        $reloadedResource = $this->adapter->getResource($name);
        $this->assertCount(3, $resource->getAccesses());
        $this->assertCount(0, $reloadedResource->getAccesses());
    }
    
    public function testRemoveAllResources()
    {
        $name = 'ResourceToRemove';
        
        $this->adapter->addResource($name);
        $this->assertNotEmpty($this->adapter->getResources());
        
        $this->adapter->removeResources();
        
        $this->assertEmpty($this->adapter->getResources());
    }

    public function testPermissions()
    {
        $acl = $this->acl;
        
        $roleManager = $acl->getRoleManager();
        $resourceManager = $acl->getResourceManager();

        $roleManager->add('Editor', 'Content editor');
        $this->assertInstanceOf('\Phalcon\Acl\RoleInterface', $roleManager->getRole('Editor'));
        
        $resourceManager->add('mvc:wiki:Frontend\Handbook', "Wiki hand books", array("index", "edit", "add", "delete"));
        $resourceManager->add('mvc:wiki:Frontend\Articles', "Wiki articles", array("index", "add"));

        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', array('delete'));
        
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
        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook', array('delete'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Wiki', 'delete'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Editor', 'mvc:wiki:Frontend\Wiki', 'test'));

        $roleManager->add('SuperAdmin', 'Super hero');
        $resourceManager->add('all', 'All and all', array('*'));
        $acl->allow('SuperAdmin', 'all', '*');

        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('SuperAdmin', 'mvc:wiki:Frontend\Wiki', 'delete'));
    }
} 