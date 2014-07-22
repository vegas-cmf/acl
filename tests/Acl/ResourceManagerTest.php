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

class ResourceManagerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Vegas\Security\Acl
     */
    protected $acl;
    
    /**
     * \Vegas\Security\Acl\ResourceManager
     */
    protected $manager;
    
    /**
     * Helper function to check whether a resource with name exists
     * @param string $name
     */
    public function assertContainsResourceWithName($name)
    {
        $this->assertNotEmpty(array_filter($this->manager->getResources(),
            function($resource) use ($name) {
                return $resource->getName() === $name;
            })
        );
    }
    
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
        $this->manager = $this->acl->getResourceManager();
    }
    
    public function testConstructor()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl\ResourceManager', $this->manager);
    }
    
    public function testCannotAddResourceWithEmptyName()
    {
        $name = '';
        try {
            $this->manager->add($name, 'Description of resource');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Exception\InvalidResourceNameException', $e);
        }
        $this->assertFalse($this->manager->isResource($name));
    }
    
    public function testWillAddResource()
    {
        $name1 = 'Fake resource';
        $name2 = 'Fake resource with accesses';
        
        $this->assertFalse($this->manager->isResource($name1));
        $this->assertFalse($this->manager->isResource($name2));
        
        $oldResourceCount = count($this->manager->getResources());
        
        $this->assertTrue($this->manager->add($name1, 'Temporary resource'));
        
        $this->assertTrue($this->manager->add($name2, '', ['first', 'second']));
        
        $newResourceCount = count($this->manager->getResources());
        $this->assertEquals($newResourceCount, 2 + $oldResourceCount);
        
        $this->assertTrue($this->manager->isResource($name1));
        $this->assertTrue($this->manager->isResource($name2));
        
        $this->assertContainsOnlyInstancesOf('\Vegas\Security\Acl\Resource', $this->manager->getResources());
        $this->assertContainsResourceWithName($name1);
        $this->assertContainsResourceWithName($name2);
        
        foreach ($this->manager->getResources() as $resource) {
            if ($resource->getName() === $name1) {
                $this->assertEmpty($resource->getAccesses());
            } else if ($resource->getName() === $name2) {
                $this->assertNotEmpty($resource->getAccesses());
                $this->assertCount(2, $resource->getAccesses());
            }
        }
    }
    
    public function testCannotAddAccessForNonexistingResource()
    {
        try {
            $this->manager->addAccess('NonExistingResource', 'whatever');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Exception', $e);
        }
    }
    
    /**
     * @depends testWillAddResource
     */
    public function testWillAddAccessForResource()
    {
        $name = 'Fake resource';
        $access = 'whatever';
        
        $result = $this->manager->addAccess($name, $access);
        $this->assertTrue($result);
        
        foreach ($this->manager->getResources() as $resource) {
            if ($resource->getName() === $name) {
                $this->assertNotEmpty($resource->getAccesses());
                $this->assertArrayHasKey($access, $resource->getAccesses());
            }
        }
    }
    
    /**
     * @depends testWillAddResource
     */
    public function testWillAddMultipleAccessesForResource()
    {
        $name = 'Fake resource with accesses';
        $this->assertContainsResourceWithName($name);
        
        $access1 = 'three';
        $access2 = 'four';
        
        $result = $this->manager->addAccess($name, [$access1, $access2]);
        $this->assertTrue($result);
        
        foreach ($this->manager->getResources() as $resource) {
            if ($resource->getName() === $name) {
                $accesses = $resource->getAccesses();
                $this->assertCount(4, $accesses);
                $this->assertArrayHasKey($access1, $accesses);
                $this->assertArrayHasKey($access2, $accesses);
            }
        }
    }
    
    /**
     * @depends testWillAddAccessForResource
     */
    public function testWillRemoveAccessForResource()
    {
        $name = 'Fake resource';
        $access = 'whatever';
        
        $result = $this->manager->removeAccess($name, $access);
        $this->assertTrue($result);
        
        foreach ($this->manager->getResources() as $resource) {
            if ($resource->getName() === $name) {
                $this->assertArrayNotHasKey($access, $resource->getAccesses());
            }
        }
    }
    
    /**
     * @depends testWillAddMultipleAccessesForResource
     */
    public function testWillRemoveMultipleAccessesForResource()
    {
        $name = 'Fake resource with accesses';
        $this->assertContainsResourceWithName($name);
        
        $access1 = 'three';
        $access2 = 'four';
        
        $result = $this->manager->removeAccess($name, [$access1, $access2]);
        $this->assertTrue($result);
        
        foreach ($this->manager->getResources() as $resource) {
            if ($resource->getName() === $name) {
                $accesses = $resource->getAccesses();
                $this->assertCount(2, $accesses);
                $this->assertArrayNotHasKey($access1, $accesses);
                $this->assertArrayNotHasKey($access2, $accesses);
            }
        }
    }
}
