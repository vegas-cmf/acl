<?php
/**
 * This file is part of Vegas package
 *
 * @author Krzysztof Kaplon <krzysztof@kaplon.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Tests\Acl\Adapter\Mysql\Model;

use Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclRole,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclResource,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess;
use Phalcon\Acl;

class AclResourceAccessTest extends \PHPUnit_Framework_TestCase
{
    public function testGetAccessLists()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'getAccessListsResource',
            'description'   => 'sna fu bar',
            'scope'         => ''
        ]);
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $resourceModel->getDirtyState());

        $accessModel = new AclResourceAccess;
        $accessModel->initialize();
        $result = $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => ''
        ]);

        $this->assertTrue($result);
        $this->assertEquals(AclResourceAccess::DIRTY_STATE_PERSISTENT, $accessModel->getDirtyState());

        $roleModel = new AclRole;
        $status = $roleModel->create([
            'name'          => 'getAccessListsRole',
            'description'   => '',
            'removable'     => 1
        ]);
        
        $this->assertTrue($result);
        $this->assertEquals(AclRole::DIRTY_STATE_PERSISTENT, $roleModel->getDirtyState());

        $aclModel = new AclAccessList;
        $result = $aclModel->create([
            'acl_role_id'            => $roleModel->id,
            'acl_resource_id'        => $resourceModel->id,
            'acl_resource_access_id' => $accessModel->id,
            'allowed'                => Acl::ALLOW
        ]);
        
        $this->assertTrue($result);
        $this->assertEquals(AclAccessList::DIRTY_STATE_PERSISTENT, $aclModel->getDirtyState());

        $list = $accessModel->getAccessLists();
        $this->assertCount(1, $list);
        $this->assertArrayHasKey(0, $list);
        $this->assertSame($list[0]->id, $aclModel->id);
    }

    public function testGetResource()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'getAclResourceResource',
            'description'   => 'sna fu bar',
            'scope'         => ''
        ]);
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $resourceModel->getDirtyState());

        $accessModel = new AclResourceAccess;
        $result = $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => null
        ]);
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $resourceModel->getDirtyState());

        $resource = $accessModel->getResource();
        $this->assertEquals($resource->id, $resourceModel->id);
    }

    public function testIsWildcard()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'IsWildcardResource',
            'description'   => 'foo bar bazz 1 2',
            'scope'         => ''
        ]);
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $resourceModel->getDirtyState());

        $accessModel = new AclResourceAccess;
        $result = $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => '*',
            'description'       => '',
            'inherit'           => null
        ]);
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $resourceModel->getDirtyState());

        $this->assertTrue($accessModel->isWildcard());

        $accessModel->name = 'not wildcard test foo';

        $this->assertFalse($accessModel->isWildcard());
    }
}