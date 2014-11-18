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
    Phalcon\Acl,
    Vegas\Tests\Cli\TestCase;

class RoleTaskTest extends TestCase
{
    /**
     * @var \Vegas\Security\Acl\RoleManager
     */
    private $roleManager;

    /**
     * @var \Vegas\Security\Acl\ResourceManager
     */
    private $resourceManager;

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
        parent::setUp();
        $this->reloadManagers();
    }

    /**
     * Shorthand for more descriptive CLI command testing
     * @param string $command full command string to be called
     * @return string
     */
    protected function runCliAction($command)
    {
        $this->bootstrap->setArguments(str_getcsv($command, ' '));

        ob_start();

        $this->bootstrap->setup()->run();
        $result = ob_get_contents();

        ob_end_clean();

        return $result;
    }

    private function reloadManagers()
    {
        $acl = $this->di->get('acl')->invalidate();
        $this->roleManager = $acl->getRoleManager();
        $this->resourceManager = $acl->getResourceManager();
    }

    /**
     * Verifies files under app/modules/_MODULE_/controllers path are used to build resource list
     */
    public function testBuildAction()
    {
        $this->assertFalse($this->resourceManager->isResource('all'));
        $this->assertFalse($this->resourceManager->isResource('mvc:foo:Frontend-Crud'));
        $this->assertFalse($this->resourceManager->isResource('mvc:foo:Frontend-Example'));

        $result = $this->runCliAction('cli/cli.php vegas:security_acl:role build');
        $this->reloadManagers();

        $this->assertContains('Success.', $result);
        $this->assertTrue($this->resourceManager->isResource('all'));
        $this->assertTrue($this->resourceManager->isResource('mvc:foo:Frontend-Crud'));
        $this->assertTrue($this->resourceManager->isResource('mvc:foo:Frontend-Example'));
    }

    /**
     * Populates application database with predefined roles: Guest and SuperAdmin.
     * Sets up all privileges to SuperAdmin user as well therefore resource list must be generated first.
     * @depends testBuildAction
     */
    public function testSetupAction()
    {
        $this->assertFalse($this->roleManager->isRole('Guest'));
        $this->assertFalse($this->roleManager->isRole('SuperAdmin'));
        $this->assertTrue($this->resourceManager->isResource('all'));

        $result = $this->runCliAction('cli/cli.php vegas:security_acl:role setup');
        $this->reloadManagers();

        $this->assertContains('Success.', $result);
        $this->assertTrue($this->roleManager->isRole('Guest'));
        $this->assertTrue($this->roleManager->isRole('SuperAdmin'));
    }

    /**
     * @depends testSetupAction
     */
    public function testAddAction()
    {
        $this->assertFalse($this->roleManager->isRole('Manager'));

        $result1 = $this->runCliAction('cli/cli.php vegas:security_acl:role add -n Manager -d "Manages regular users"');
        $result2 = $this->runCliAction('cli/cli.php vegas:security_acl:role add -n Editor');
        $this->reloadManagers();

        $this->assertContains('Success.', $result1);
        $this->assertContains('Success.', $result2);

        $this->assertTrue($this->roleManager->isRole('Manager'));
        $this->assertTrue($this->roleManager->isRole('Editor'));
        $this->assertEquals('Manages regular users', $this->roleManager->getRole('Manager')->getDescription());
        $this->assertEquals('', $this->roleManager->getRole('Editor')->getDescription());
    }

    /**
     * @depends testAddAction
     */
    public function testRemoveAction()
    {
        $this->assertTrue($this->roleManager->isRole('Editor'));

        $result = $this->runCliAction('cli/cli.php vegas:security_acl:role remove -n Editor');
        $this->reloadManagers();

        $this->assertContains('Success.', $result);

        $this->assertFalse($this->roleManager->isRole('Editor'));
    }

    /**
     * @depends testAddAction
     */
    public function testAllowAction()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl\Role', $this->roleManager->getRole('Manager'));

        $acl = $this->di->get('acl');
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Example', 'index'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'index'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'show'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'delete'));

        $resultOne = $this->runCliAction('cli/cli.php vegas:security_acl:role allow -n Manager -r mvc:foo:Frontend-Crud -a index');
        $this->assertContains('Success.', $resultOne);

        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Example', 'index'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'index'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'show'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'delete'));

        $resultMultiple = $this->runCliAction('cli/cli.php vegas:security_acl:role allow -n Manager -r mvc:foo:Frontend-Crud');
        $this->assertContains('Success.', $resultMultiple);

        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Example', 'index'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'index'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'show'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'delete'));
    }

    /**
     * @depends testAllowAction
     */
    public function testDenyAction()
    {
        $this->assertInstanceOf('\Vegas\Security\Acl\Role', $this->roleManager->getRole('Manager'));

        $acl = $this->di->get('acl');
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'index'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'show'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'delete'));

        $resultOne = $this->runCliAction('cli/cli.php vegas:security_acl:role deny -n Manager -r mvc:foo:Frontend-Crud -a delete');
        $this->assertContains('Success.', $resultOne);

        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'index'));
        $this->assertEquals(Acl::ALLOW, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'show'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'delete'));

        $resultMultiple = $this->runCliAction('cli/cli.php vegas:security_acl:role deny -n Manager -r mvc:foo:Frontend-Crud');
        $this->assertContains('Success.', $resultMultiple);

        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'index'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'show'));
        $this->assertEquals(Acl::DENY, $acl->isAllowed('Manager', 'mvc:foo:Frontend-Crud', 'delete'));
    }
}