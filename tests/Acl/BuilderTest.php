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
    \Vegas\Security\Acl\Builder,
    \Phalcon\Annotations\Adapter\Files;

class BuilderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Object to be tested.
     *
     * @var \Vegas\Security\Acl\Builder
     */
    private $obj;

    /**
     * Modules config for testing.
     *
     * @var array
     */
    private $modules;

    /**
     * Predefined resources config for testing.
     *
     * @var array
     */
    private $predefinedResources;

    public function setUp()
    {
        $this->modules = [
            'Foo' => [
                'className' => 'Foo\Controllers',
                'path' => TESTS_ROOT_DIR . '/fixtures/app/modules/Foo/Module.php',
            ]
        ];

        $this->predefinedResources = [
            'mvc:foo:Test\Baz' => [
                'description' => 'Foo bar description',
                'accessList' => ['index', 'test'],
            ],
        ];

        $this->obj = new Builder($this->modules, $this->predefinedResources);
        $this->assertInstanceOf('\Vegas\Security\Acl\Builder', $this->obj);
    }

    public function tearDown()
    {
        $this->obj = null;
        $this->modules = null;
        $this->predefinedResources = null;
    }

    public function testSetupAnnotationsReaderUsesOtherAdapter()
    {
        $filesAdapter = new Files;
        $this->obj->setupAnnotationsReader($filesAdapter);

        $annotationsReader = $this->getInaccessibleMethodValue($this->obj, 'getAnnotationsReader');
        $this->assertSame($filesAdapter, $annotationsReader);
    }

    public function testBuildAcl()
    {
        $build = $this->obj->build();

        $modules = $this->getInaccessiblePropertyValue($this->obj, 'modules');
        $predefinedResources = $this->getInaccessiblePropertyValue($this->obj, 'predefinedResources');

        $this->assertSame($this->modules, $modules);
        $this->assertSame($this->predefinedResources, $predefinedResources);
        $this->assertCount(3, $build);

        $expectedBuildResult = [
            // CrudController
            [
                'name' => 'mvc:foo:Frontend\Crud',
                'description' => 'Example crud controller',
                'accessList' => [
                    // original methods
                    'index' => [
                        'name' => 'index',
                        'description' => 'Index action',
                        'inherit' => '',
                    ],

                    'show' => [
                        'name' => 'show',
                        'description' => 'Show action',
                        'inherit' => '',
                    ],

                    'list' => [
                        'name' => 'list',
                        'description' => 'List action',
                        'inherit' => '',
                    ],

                    'test' => [
                        'name' => 'test',
                        'description' => 'Test action',
                        'inherit' => ['test2'],
                    ],
                    // parents' methods
                    'new' => [
                        'name' => 'new',
                        'description' => 'Create a new record',
                        'inherit' => ['create'],
                    ],
                    'edit' => [
                        'name' => 'edit',
                        'description' => 'Record edit',
                        'inherit' => ['update'],
                    ],
                    'delete' => [
                        'name' => 'delete',
                        'description' => 'Delete a record',
                        'inherit' => '',
                    ],
                ],
                'scope' => 'frontend',
            ],
            // ExampleController
            [
                'name' => 'mvc:foo:Frontend\Example',
                'description' => 'Example controller',
                'accessList' => [
                    'index' => [
                        'name' => 'index',
                        'description' => 'Index action',
                        'inherit' => '',
                    ],
                ],
                'scope' => 'frontend',
            ],
            // Predefined resource
            [
                'name' => 'mvc:foo:Test\Baz',
                'description' => 'Foo bar description',
                'accessList' => ['index', 'test'],
            ],
        ];

        $this->assertSame($expectedBuildResult, $build);
    }

    public function testBuildSkipsModuleIfControllerDirConfigIsIncorrect()
    {
        $modules = [
            'nec' => [
                'className' => 'NotExisting\Controller',
                'path' => 'not/existing/path',
            ]
        ];

        $this->obj = new Builder($modules);
        $build = $this->obj->build();

        $this->assertEmpty($build);
    }

    private function getInaccessiblePropertyValue($obj, $propertyName)
    {
        $reflectionProperty = new \ReflectionProperty($obj, $propertyName);
        $reflectionProperty->setAccessible(true);

        return $reflectionProperty->getValue($obj);
    }

    private function getInaccessibleMethodValue($obj, $methodName)
    {
        $reflectionMethod = new \ReflectionMethod($obj, $methodName);
        $reflectionMethod->setAccessible(true);

        return $reflectionMethod->invoke($obj);
    }
}