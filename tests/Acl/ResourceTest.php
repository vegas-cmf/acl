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
    \Vegas\Security\Acl\Resource;

class ResourceTest extends \PHPUnit_Framework_TestCase
{
    public function testHasAccesses()
    {
        $accessName = 'FooAccessNameTest';
        $accesses = [
            [
                'access_name' => $accessName,
                'access_description' => 'some description',
            ]
        ];

        $resource = new Resource('testResourceFoo', 'DescriptionOfTheTestResource');

        $this->assertFalse($resource->hasAccess($accessName));
        $resource->setAccesses($accesses);
        $this->assertTrue($resource->hasAccess($accessName));
    }
}