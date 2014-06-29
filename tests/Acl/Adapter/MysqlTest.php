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
use Vegas\Security\Acl\Adapter\Mysql\Model\AclRole;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclResource;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess;

class MysqlTest extends \PHPUnit_Framework_TestCase
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
        foreach (AclResource::find() as $resource) {
            $resource->delete();
        }
        foreach (AclRole::find() as $role) {
            $role->delete();
        }
        $resource = new AclResource;
        $resource->create([
            'name'          => AclResource::WILDCARD,
            'description'   => 'All in all (built-in)',
        ]);
        (new AclResourceAccess)->create([
            'name'            => AclResourceAccess::WILDCARD,
            'description'     => 'All in all (built-in)',
            'acl_resource_id' => $resource->id
        ]);
    }
    
    public function setUp()
    {
        $this->acl = DI::getDefault()->get('acl_mysql');
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

        $acl->deny('Editor', 'mvc:wiki:Frontend\Handbook');
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