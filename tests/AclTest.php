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
 
namespace Vegas\Tests;

use Phalcon\DI;

class AclTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Vegas\Security\Acl
     */
    protected $acl;
    
    public function setUp()
    {
        $this->acl = DI::getDefault()->get('acl');
    }
    
    public function assertPreConditions()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl', $this->acl);
    }
    
    public function testGetAdapter()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\AdapterInterface', $this->acl->getAdapter());
    }
    
    public function testGetResourceManager()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl\ResourceManager', $this->acl->getResourceManager());
    }
    
    public function testGetRoleManager()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl\RoleManager', $this->acl->getRoleManager());
    }
    
    /**
     * @depends testGetAdapter
     */
    public function testAclHasShorthandAdapterMethods()
    {
        $methods = get_class_methods($this->acl->getAdapter());
        
        foreach ($methods as $methodName) {
            $canBeCalled = is_callable([$this->acl, $methodName]);
            $this->assertTrue($canBeCalled);
        }
    }

    /**
     * @depends testGetResourceManager
     * @depends testGetRoleManager
     */
    public function testInvalidationGeneratesNewManagers()
    {
        $oldResourceManager = $this->acl->getResourceManager();
        $oldRoleManager = $this->acl->getRoleManager();

        $this->acl->invalidate();

        $this->assertNotSame($oldResourceManager, $this->acl->getResourceManager());
        $this->assertNotSame($oldRoleManager, $this->acl->getRoleManager());
    }
}
