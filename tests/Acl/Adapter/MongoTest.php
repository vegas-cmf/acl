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
} 