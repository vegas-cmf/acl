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
 
namespace Vegas\Tests\Acl\Adapter;

use Phalcon\DI,
    \Vegas\Security\Acl\Task\RoleTask;

class RoleTaskTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Object to be tested.
     * 
     * @var Role
     */
    private $obj;
    
    public function setUp()
    {
        $this->obj = new RoleTask();
    }
    
    public function tearDown()
    {
        $this->obj = null;
    }
    
    public function testSetOptions()
    {
        $expectedOptions = [
            'setup',
            'add',
            'remove',
            'allow',
            'deny',
            'build',
        ];
        
        $this->obj->setOptions();
        $actions = $this->getInaccessiblePropertyValue($this->obj, 'actions', 'Vegas\Cli\Task');
        
        $this->assertSame($expectedOptions, array_keys($actions));
    }
    
    public function testSetupAction()
    {
        $acl = DI::getDefault()->get('acl');
        $roleManager = $acl->getRoleManager();
        $resourceManager = $acl->getResourceManager();
        
        $this->obj->setupAction();
        
        $this->assertTrue($roleManager->isRole('Guest'));
        $this->assertTrue($roleManager->isRole('SuperAdmin'));
        $this->assertTrue($resourceManager->isResource('all'));
        $this->assertContains('Success.', $this->obj->getOutput());
    }
    
    public function testAddAction()
    {
        $this->markTestIncomplete('Set up run configuration for dispatcher to work.');
        $this->obj->setOptions();
        $this->obj->addAction();
        
        $this->assertContains('Success.', $this->obj->getOutput());
    }
    
    public function testRemoveAction()
    {
        $this->markTestIncomplete('Set up run configuration for dispatcher to work.');
        $this->obj->setOptions();
        
        $actions = $this->getInaccessiblePropertyValue($this->obj, 'actions', 'Vegas\Cli\Task');
        $this->assertInstanceOf('\Vegas\Cli\Task\Action', $actions['setup']);
        
        $this->obj->removeAction();
        $this->assertContains('Success.', $this->obj->getOutput());
    }

    public function testAllowAction()
    {
        $this->markTestIncomplete('Set up run configuration for dispatcher to work.');
        $this->obj->allowAction();
        $this->assertContains('Success.', $this->obj->getOutput());
    }
    
    public function testDenyAction()
    {
        $this->markTestIncomplete('Set up run configuration for dispatcher to work.');
        $this->obj->denyAction();
        $this->assertContains('Success.', $this->obj->getOutput());
    }
    
    public function testBuildAction()
    {
        $this->markTestIncomplete('Set up run configuration for dispatcher to work.');
        $this->obj->buildAction();
        $this->assertContains('Success.', $this->obj->getOutput());
    }
    
    private function getInaccessiblePropertyValue($obj, $propertyName, $parent = null)
    {
        $parent = empty($parent) ? $obj : $parent;
        
        $reflectionProperty = new \ReflectionProperty($parent, $propertyName);
        $reflectionProperty->setAccessible(true);

        return $reflectionProperty->getValue($obj);
    }
}