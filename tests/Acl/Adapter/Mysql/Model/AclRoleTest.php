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

use Vegas\Security\Acl\Adapter\Mysql\Model\AclRole,
    Vegas\Security\Acl\Adapter\Mysql\Model\AclResource;

class AclRoleTestTest extends \PHPUnit_Framework_TestCase
{

    public function testToString()
    {
        $roleName = 'toStringAclRoleTest';
        $roleModel = new AclRole;
        $roleModel->initialize();
        
        $result = $roleModel->create([
            'name'          => $roleName,
            'description'   => '',
            'removable'     => 1
        ]);
        $this->assertTrue($result);
        $this->assertEquals(AclResource::DIRTY_STATE_PERSISTENT, $roleModel->getDirtyState());

        $this->assertSame((string)$roleModel, $roleName);
    }
}