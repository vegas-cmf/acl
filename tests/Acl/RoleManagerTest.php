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

class RoleManagerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Vegas\Security\Acl
     */
    protected $acl;
    
    /**
     * \Vegas\Security\Acl\RoleManager
     */
    protected $manager;
    
    /**
     * Helper function to check whether a role with name exists
     * @param string $name
     */
    public function assertContainsRoleWithName($name)
    {
        $this->assertNotEmpty(array_filter($this->manager->getRoles(),
            function($role) use ($name) {
                return $role->getName() === $name;
            })
        );
    }
    
    public function setUp()
    {
        $this->acl = DI::getDefault()->get('acl');
        $this->manager = $this->acl->getRoleManager();
    }
    
    public function testCannotAddRoleWithEmptyName()
    {
        $name = '';
        try {
            $this->manager->add($name, 'Description of role');
            $this->fail('Exception not triggered');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Exception\InvalidRoleNameException', $e);
        }
        $this->assertFalse($this->manager->isRole($name));
    }
    
    public function testWillAddRole()
    {
        $name1 = 'Fake role';
        $name2 = 'Fake built-in role';
        
        $this->assertFalse($this->manager->isRole($name1));
        $this->assertFalse($this->manager->isRole($name2));
        
        $oldRoleCount = count($this->manager->getRoles());
        
        $this->assertTrue($this->manager->add($name1, 'Temporary role'));
        $this->assertTrue($this->manager->add($name2, 'Role which cannot be removed', false));
        
        $newRoleCount = count($this->manager->getRoles());
        $this->assertEquals($newRoleCount, 2 + $oldRoleCount);
        
        $this->assertTrue($this->manager->isRole($name1));
        $this->assertTrue($this->manager->isRole($name2));
        
        $this->assertContainsOnlyInstancesOf('\Vegas\Security\Acl\Role', $this->manager->getRoles());
        $this->assertContainsRoleWithName($name1);
        $this->assertContainsRoleWithName($name2);
        $this->assertInstanceOf('\Vegas\Security\Acl\Role', $this->manager->getRole($name1));
        $this->assertInstanceOf('\Vegas\Security\Acl\Role', $this->manager->getRole($name2));
    }
    
    public function testCannotGetNonexistingRole()
    {
        $this->assertFalse($this->manager->isRole('NonExistingRole'));
        try {
            $this->manager->getRole('NonExistingRole');
            $this->fail('Exception not triggered');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Exception\RoleDoesNotExistException', $e);
        }
    }
    
    public function testCannotRemoveNonexistingRole()
    {
        $this->assertFalse($this->manager->isRole('NonExistingRole'));
        try {
            $this->manager->dropRole('NonExistingRole');
            $this->fail('Exception not triggered');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Exception\RoleDoesNotExistException', $e);
        }
    }
    
    /**
     * @depends testWillAddRole
     */
    public function testWillDropRole()
    {
        $name = 'Fake role';
        $this->assertTrue($this->manager->isRole($name));
        
        $this->manager->dropRole($name);
        
        $this->assertFalse($this->manager->isRole($name));
    }
}
