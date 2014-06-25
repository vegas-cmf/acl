<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security;

use Phalcon\Acl\AdapterInterface;
use Phalcon\DI\InjectionAwareInterface;
use Vegas\Security\Acl\ResourceManager;
use Vegas\Security\Acl\RoleManager;

/**
 * Class Acl
 *
 * @method setDefaultAction($defaultAccess)
 * @method getDefaultAction()
 * @method addRole($role, $accessInherits=null)
 * @method addInherit($roleName, $roleToInherit)
 * @method isRole($roleName)
 * @method isResource($resourceName)
 * @method addResource($resource, $accessList=null)
 * @method addResourceAccess($resourceName, $accessList)
 * @method dropResourceAccess($resourceName, $accessList)
 * @method allow($roleName, $resourceName, $access = '*')
 * @method deny($roleName, $resourceName, $access = '*')
 * @method isAllowed($role, $resource, $access)
 * @method removeResources()
 * @method removeResourceAccesses()
 * @method getActiveRole()
 * @method getActiveResource()
 * @method getActiveAccess()
 * @method getRoles()
 * @method getResources()
 *
 * @package Vegas\Security\Acl
 */
class Acl implements InjectionAwareInterface
{
    use \Vegas\DI\InjectionAwareTrait;

    /**
     * @var AdapterInterface
     */
    protected $adapter;

    /**
     * @var \Vegas\Security\Acl\ResourceManager
     */
    protected $resourceManager;

    /**
     * @var \Vegas\Security\Acl\RoleManager
     */
    protected $roleManager;

    /**
     * @param AdapterInterface $adapter
     */
    public function __construct(AdapterInterface $adapter)
    {
        $this->setAdapter($adapter);
    }

    /**
     * @param $name
     * @param $args
     * @return mixed
     */
    public function __call($name, $args)
    {
        return call_user_func_array(array($this->adapter, $name), $args);
    }

    /**
     * @param AdapterInterface $adapter
     */
    protected function setAdapter(AdapterInterface $adapter)
    {
        $this->adapter = $adapter;
    }

    /**
     * @return AdapterInterface
     */
    public function getAdapter()
    {
        return $this->adapter;
    }

    /**
     * @return ResourceManager
     */
    public function getResourceManager()
    {
        if (!$this->resourceManager) {
            $this->resourceManager = new ResourceManager($this->getAdapter());
        }

        return $this->resourceManager;
    }

    /**
     * @return RoleManager
     */
    public function getRoleManager()
    {
        if (!$this->roleManager) {
            $this->roleManager = new RoleManager($this->getAdapter());
        }

        return $this->roleManager;
    }
}
