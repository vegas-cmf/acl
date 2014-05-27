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

namespace Vegas\Security\Acl\Adapter;

use \Vegas\Security\Acl\Exception as AclException;

/**
 *
 * @package Vegas\Security\Acl\Adapter
 */
class Exception extends AclException
{
    protected $message = "ACL adapter error";
}
 