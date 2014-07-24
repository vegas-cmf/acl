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
class ResourceNotExistsException extends AclAdapterException
{
    protected $message = "Resource does not exist";

    /**
     * @param string $resourceName
     */
    public function __construct($resourceName = '')
    {
        $this->message = sprintf("Resource '%s' does not exist", $resourceName);
    }
}
 