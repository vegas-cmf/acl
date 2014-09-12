<?php

use Phinx\Migration\AbstractMigration;

class AddDbTablePrefix extends AbstractMigration
{
    /**
     * Migrate Up.
     */
    public function up()
    {
        $this->table('acl_roles')->rename('vegas_acl_roles');
        $this->table('acl_resources')->rename('vegas_acl_resources');
        $this->table('acl_resources_accesses')->rename('vegas_acl_resources_accesses');
        $this->table('acl_access_list')->rename('vegas_acl_access_list');
    }

    /**
     * Migrate Down.
     */
    public function down()
    {
        $this->table('vegas_acl_roles')->rename('acl_roles');
        $this->table('vegas_acl_acl_resources')->rename('acl_resources');
        $this->table('vegas_acl_acl_resources_accesses')->rename('acl_resources_accesses');
        $this->table('vegas_acl_acl_access_list')->rename('acl_access_list');
    }
}