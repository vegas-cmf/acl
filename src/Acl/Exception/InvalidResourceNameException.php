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
 * @package Vegas\Cli\Task\Acl
 */
class InvalidResourceNameException extends AclException
{
    protected $message = "Invalid resource name";
}
 