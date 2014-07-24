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
 
namespace Vegas\Tests\Acl\Adapter\Mysql;

use Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclRole,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclResource,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess;
use Phalcon\Acl;

class AclResourceTest extends \PHPUnit_Framework_TestCase
{    
    public function testCreateResource()
    {
        $resource = new AclResource;
        $this->assertNull($resource->id);
        
        $result = $resource->save([
            'name'          => 'CreatedResource',
            'description'   => 'Sample description',
            'scope'         => ''
        ]);
        
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $resource->getDirtyState());
    }
    
    /**
     * @depends testCreateResource
     */
    public function testFindByNameMethod()
    {
        $this->assertFalse(AclResource::findFirstByName('NonExistingResource'));
        
        $resource = AclResource::findFirstByName('CreatedResource');
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource', $resource);
    }
    
    /**
     * @depends testCreateResource
     */
    public function testCreateRelatedModels()
    {
        $resourceModel = AclResource::findFirstByName('CreatedResource');
        
        $roleModel = new AclRole;
        $roleModel->create([
            'name'          => 'guest',
            'description'   => '',
            'removable'     => true
        ]);
        $this->assertEquals(AclRole::DIRTY_STATE_PERSISTENT, $roleModel->getDirtyState());
        
        $accessModel = new AclResourceAccess;
        $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => null
        ]);
        $this->assertEquals(AclResourceAccess::DIRTY_STATE_PERSISTENT, $accessModel->getDirtyState());
        
        $aclModel = new AclAccessList;
        $aclModel->create([
            'acl_role_id'            => $roleModel->id,
            'acl_resource_id'        => $resourceModel->id,
            'acl_resource_access_id' => $accessModel->id,
            'allowed'                => Acl::ALLOW
        ]);
        $this->assertEquals(AclAccessList::DIRTY_STATE_PERSISTENT, $aclModel->getDirtyState());
    }
    
    /**
     * @depends testCreateRelatedModels
     */
    public function testGetRelatedModels()
    {
        $resource = AclResource::findFirstByName('CreatedResource');
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource', $resource);
        
        $this->assertEquals(1, count($resource->getAccessLists()));
        
        $this->assertEquals(1, count($resource->getResourceAccesses()));
    }
    
    /**
     * @depends testCreateRelatedModels
     */
    public function testGetResourceAccessesArray()
    {
        $resource = AclResource::findFirstByName('CreatedResource');
        $this->assertInstanceOf('\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource', $resource);
        
        $this->assertInternalType('array', $resource->getAccessesAsArray());
        foreach ($resource->getAccessesAsArray() as $access) {
            $this->assertArrayHasKey('access_name', $access);
            $this->assertArrayHasKey('access_description', $access);
        }
    }
}