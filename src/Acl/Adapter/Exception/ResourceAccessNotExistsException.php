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

namespace Vegas\Security\Acl\Adapter\Exception;

use Vegas\Security\Acl\Adapter\Exception as AclAdapterException;

/**
 *
 * @package Vegas\Security\Acl\Adapter\Exception
 */
class ResourceAccessNotExistsException extends AclAdapterException
{
    protected $message = "Resource access setting does not exist";

    /**
     * @param string $resourceName
     */
    public function __construct($resourceName = '')
    {
        $this->message = sprintf("Resource access setting %s does not exist", $resourceName);
    }
}
 