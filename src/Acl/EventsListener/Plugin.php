<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security\Acl\EventsListener;

use Phalcon\Events\Event,
    Phalcon\Mvc\User\Plugin as UserPlugin,
    Phalcon\Mvc\Dispatcher,
    Phalcon\Acl;
use Vegas\Security\Acl\Exception\NotAllowedException;
use Vegas\Security\Acl\Role;

/**
 *
 * @package Vegas\Security\Acl\EventsListener
 */
class Plugin extends UserPlugin
{
    /**
     * @param Event $event
     * @param Dispatcher $dispatcher
     * @throws \Vegas\Security\Acl\Exception\NotAllowedException
     */
    public function beforeExecuteRoute(Event $event, Dispatcher $dispatcher)
    {
        $authentication = $this->ensureAuthentication();
        if ($authentication) {
            $role = $authentication->getIdentity()->getRole();
        } else {
            $role = Role::GUEST;
        }
        $resource = $this->getResourceName($dispatcher);
        $access = $dispatcher->getActionName();
        $allowed = $this->di->get('acl')->isAllowed($role, $resource, $access);
        if ($allowed != Acl::ALLOW) {
            $this->flash->error('acl.error.not_allowed');
            throw new NotAllowedException();
        }
    }

    /**
     * @return bool|object
     */
    protected function ensureAuthentication()
    {
        $matchedRoute = $this->router->getMatchedRoute();
        $paths = $matchedRoute->getPaths();

        if (!isset($paths['auth'])) {
            //authentication is disabled by default
            $authSessionKey = false;
        } else {
            $authSessionKey = $paths['auth'];
        }

        if (!$authSessionKey) {
            return false;
        }

        if (!$this->getDI()->has($authSessionKey)) {
            return false;
        }

        return $this->getDI()->get($authSessionKey);
    }

    /**
     * @param Dispatcher $dispatcher
     * @return string
     */
    protected function getResourceName(Dispatcher $dispatcher)
    {
        $module = $dispatcher->getModuleName();
        $controller = $dispatcher->getControllerName();

        return sprintf('mvc:%s:%s', lcfirst($module), str_replace('\\', '-', $controller));
    }
} 
