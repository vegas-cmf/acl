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

namespace Vegas\Security\Acl\Adapter;

use \Phalcon\Acl\AdapterInterface as AclAdapterInterface;

/**
 *
 * @package Vegas\Security\Acl\Adapter
 */
interface AdapterInterface extends AclAdapterInterface
{
    /**
     * @return mixed
     */
    public function removeResources();

    /**
     * @return mixed
     */
    public function removeResourceAccesses();

}
 