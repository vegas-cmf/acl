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

namespace Vegas\Tests\Acl;

use \Phalcon\DI,
    \Vegas\Security\Acl\Role;

class RoleTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Object to be tested.
     *
     * @var \Vegas\Security\Acl\Role
     */
    private $obj;

    public function setUp()
    {
        $this->obj = new Role('testRoleFooBAr', 'some role description');
    }

    public function tearDown()
    {
        $this->obj = null;
    }

    public function testGetId()
    {
        $id = 'foo';
        $this->obj->setId($id);

        $this->assertSame($id, $this->obj->getId());
    }
}