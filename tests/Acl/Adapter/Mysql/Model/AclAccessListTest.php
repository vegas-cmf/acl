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

class AclAccessListTest extends \PHPUnit_Framework_TestCase
{
    public function testGetResource()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'getResourceResource',
            'description'   => 'test description foo',
            'scope'         => ''
        ]);
        $this->assertTrue($result);

        $roleModel = new AclRole;
        $roleModel->create([
            'name'          => 'getResourceRole',
            'description'   => '',
            'removable'     => true
        ]);

        $accessModel = new AclResourceAccess;
        $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => null
        ]);

        $aclModel = new AclAccessList;
        $aclModel->create([
            'acl_role_id'            => $roleModel->id,
            'acl_resource_id'        => $resourceModel->id,
            'acl_resource_access_id' => $accessModel->id,
            'allowed'                => Acl::ALLOW
        ]);

        $resource = $aclModel->getResource();
        $this->assertSame($resource->id, $resourceModel->id);
    }

    public function testGetResourceAccess()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'getResourceAccessResource',
            'description'   => 'foo bar 1',
            'scope'         => ''
        ]);
        $this->assertTrue($result);

        $roleModel = new AclRole;
        $roleModel->create([
            'name'          => 'getResourceAccessRole',
            'description'   => '',
            'removable'     => true
        ]);

        $accessModel = new AclResourceAccess;
        $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => null
        ]);

        $aclModel = new AclAccessList;
        $aclModel->create([
            'acl_role_id'            => $roleModel->id,
            'acl_resource_id'        => $resourceModel->id,
            'acl_resource_access_id' => $accessModel->id,
            'allowed'                => Acl::ALLOW
        ]);

        $access = $aclModel->getResourceAccess();
        $this->assertSame($access->id, $accessModel->id);
    }

    public function testGetRole()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'getRoleResource',
            'description'   => 'foo bar baz',
            'scope'         => ''
        ]);
        $this->assertTrue($result);

        $roleModel = new AclRole;
        $roleModel->create([
            'name'          => 'getRoleRole',
            'description'   => '',
            'removable'     => 1
        ]);

        $accessModel = new AclResourceAccess;
        $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => null
        ]);

        $aclModel = new AclAccessList;
        $aclModel->create([
            'acl_role_id'            => $roleModel->id,
            'acl_resource_id'        => $resourceModel->id,
            'acl_resource_access_id' => $accessModel->id,
            'allowed'                => Acl::ALLOW
        ]);

        $role = $aclModel->getRole();
        $this->assertSame($role->id, $roleModel->id);
    }

    public function testToAccessArray()
    {
        $resourceModel = new AclResource;
        $result = $resourceModel->save([
            'name'          => 'toAccessArrayResource',
            'description'   => 'foo bar baz',
            'scope'         => ''
        ]);
        $this->assertTrue($result);

        $roleModel = new AclRole;
        $roleModel->create([
            'name'          => 'toAccessArrayRole',
            'description'   => '',
            'removable'     => true
        ]);

        $accessModel = new AclResourceAccess;
        $accessModel->create([
            'acl_resource_id'   => $resourceModel->id,
            'name'              => 'index',
            'description'       => '',
            'inherit'           => null
        ]);

        $aclModel = new AclAccessList;
        $aclModel->create([
            'acl_role_id'            => $roleModel->id,
            'acl_resource_id'        => $resourceModel->id,
            'acl_resource_access_id' => $accessModel->id,
            'allowed'                => false
        ]);

        $accessArray = [
            'access_name'       => (string)$accessModel,
            'resources_name'    => (string)$resourceModel,
            'allowed'           => false
        ];

        $toAccessArray = $aclModel->toAccessArray();
        $this->assertSame($toAccessArray, $accessArray);
    }
}