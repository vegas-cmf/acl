<?php

use Phinx\Migration\AbstractMigration;
use Vegas\Security\Acl\Resource;

class AddDefaultEntriesToAclTables extends AbstractMigration
{
    /**
     * Migrate Up.
     */
    public function up()
    {
        $wildcard = Resource::WILDCARD;
        $accessWildcard = Resource::ACCESS_WILDCARD;
        $this->query("INSERT INTO acl_resources (id, name, description) VALUES (1, '{$wildcard}', 'All in all (built-in)')");
        $this->query("INSERT INTO acl_resources_accesses (id, name, description, acl_resource_id) VALUES (1, '{$accessWildcard}', 'All in all (built-in)', 1)");
    }

    /**
     * Migrate Down.
     */
    public function down()
    {
        $wildcard = Resource::WILDCARD;
        $accessWildcard = Resource::ACCESS_WILDCARD;
        $this->query("DELETE FROM acl_resources_accesses WHERE name = '{$accessWildcard}'");
        $this->query("DELETE FROM acl_resources WHERE name = '{$wildcard}'");
    }
}