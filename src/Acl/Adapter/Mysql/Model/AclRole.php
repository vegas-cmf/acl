<?php
/**
 * This file is part of Vegas package
 *
 * @author Radosław Fąfara <radek@archdevil.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security\Acl\Adapter\Mysql\Model;

use Phalcon\Mvc\Model\Relation;

/**
 * @use \Vegas\Security\Acl\Adapter\Mysql\Model\AclRole
 * @package Vegas\Security\Acl\Adapter\Mysql\Model
 *
 * Custom implementation of ACL used in MySQL databases.
 * Keeps information about role of the user.
 */
class AclRole extends \Phalcon\Mvc\Model
{
    use NameFinderTrait;
    
    const DEFAULT_ALIAS = 'aro';

    /**
     * @var integer
     */
    public $id;
    
    /**
     * @var string
     */
    public $name;
    
    /**
     * @var string
     */
    public $description;
    
    /**
     * @var integer (0|1)
     */
    public $removable;
    
    /**
     * @return string
     */
    public function __toString()
    {
        return $this->name;
    }
    
    public function initialize()
    {
        $this->hasMany("acl_role_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList", "id", [
            'alias'  => AclAccessList::DEFAULT_ALIAS,
            'foreignKey' => [
                'action' => Relation::ACTION_CASCADE
            ]
        ]);
    }
    
    public function getSource()
    {
        return 'acl_roles';
    }
    
    /**
     * @return AclAccessList[]
     */
    public function getAccessLists()
    {
        return $this->getRelated(AclAccessList::DEFAULT_ALIAS);
    }

}
