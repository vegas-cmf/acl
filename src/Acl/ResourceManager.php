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

namespace Vegas\Security\Acl;

use Vegas\Security\Acl\Exception\InvalidResourceNameException;

/**
 *
 * @package Vegas\Security\Acl
 */
class ResourceManager extends ManagerAbstract {

    /**
     * @return \Phalcon\Acl\ResourceInterface[]
     */
    public function getResources()
    {
        $resources = $this->adapter->getResources();

        return $resources;
    }

    /**
     * @param $name
     * @param $description
     * @param array $accessList
     * @param string $scope
     * @throws Exception\InvalidResourceNameException
     * @return bool
     */
    public function add($name, $description, $accessList = array(), $scope = '')
    {
        if (!$name) {
            throw new InvalidResourceNameException;
        }
        $resource = new Resource($name, $description);
        $resource->setScope($scope);

        $result = $this->adapter->addResource($resource, $accessList);

        return $result;
    }

    /**
     * @param $resourceName
     * @param $accessList
     * @return mixed
     */
    public function addAccess($resourceName, $accessList)
    {
        $result = $this->adapter->addResourceAccess($resourceName, $accessList);

        return $result;
    }

    /**
     * @param $resourceName
     * @param $accessList
     * @return mixed
     */
    public function removeAccess($resourceName, $accessList)
    {
        $result = $this->adapter->dropResourceAccess($resourceName, $accessList);

        return $result;
    }

    /**
     * @param $name
     * @return bool
     */
    public function isResources($name)
    {
        $result = $this->adapter->isResource($name);

        return $result;
    }
}
 