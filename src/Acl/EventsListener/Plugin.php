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

use Phalcon\Events\Event;
use Phalcon\Mvc\User\Plugin as UserPlugin;
use Phalcon\Mvc\Dispatcher;
use Phalcon\Acl;
use Vegas\Security\Acl\Exception\NotAllowedException;
use Vegas\Security\Acl\Role;

/**
 *
 * @package Vegas\Security\Acl\EventsListener
 */
class Plugin extends UserPlugin
{
    protected $scope = null;

    /**
     * @param Event $event
     * @param Dispatcher $dispatcher
     * @throws \Vegas\Security\Acl\Exception\NotAllowedException
     */
    public function beforeExecuteRoute(Event $event, Dispatcher $dispatcher)
    {
        $resource = $this->getResourceName($dispatcher);
        $access = $dispatcher->getActionName();

        $isAllowed = $this->isAllowedAccess($resource, $access);

        if (!$isAllowed) {
            $ex = new NotAllowedException();
            $ex->appendToMessage(' / Resource: '.$resource);
            $ex->appendToMessage(' / Access: '.$access);

            $this->dispatcher->getEventsManager()->fire('dispatch:beforeException', $this->dispatcher, $ex);
        }

        return $isAllowed;
    }

    /**
     * @param string $resource - resource name
     * @param string $access - access name
     * @return bool
     */
    protected function isAllowedAccess($resource, $access)
    {
        foreach ($this->getAuthenticationScopes() As $scope) {
            $this->scope = $scope;

            if ($scope === false) {
                // no auth access
                return true;
            }

            $authentication = $this->ensureAuthentication($scope);

            if ($authentication) {
                $role = $authentication->getIdentity()->getRole();
            } else {
                $role = Role::GUEST;
            }

            $allowed = $this->di->get('acl')->isAllowed($role, $resource, $access);

            if ($allowed == Acl::ALLOW) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return array of all used authentication scopes for current route.
     *
     * @return array
     */
    protected function getAuthenticationScopes()
    {
        $matchedRoute = $this->router->getMatchedRoute();
        $paths = $matchedRoute->getPaths();

        if (empty($paths['auth'])) {
            return array(false);
        }

        $auth = json_decode($paths['auth']);
        if (is_array($auth)) {
            return $auth;
        }

        return array($paths['auth']);
    }

    /**
     * @return bool|object
     */
    protected function ensureAuthentication($scope)
    {
        if (!$this->getDI()->has($scope)) {
            return false;
        }

        return $this->getDI()->get($scope);
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

    /**
     * @return string|null|false current scope name
     */
    public function getCurrentScopeName()
    {
        return $this->scope;
    }
} 
