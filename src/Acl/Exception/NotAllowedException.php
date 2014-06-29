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
 
namespace Vegas\Security\Acl\Exception;

use \Vegas\Security\Acl\Exception as AclException;

/**
 *
 * @package Vegas\Security\Task\Acl\Exception
 */
class NotAllowedException extends AclException
{
    protected $message = "You are not authorized to see this content";
} 