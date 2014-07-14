<?php

use Phinx\Migration\AbstractMigration;

class CreateAclTables extends AbstractMigration
{
    /**
     * Migrate Up.
     */
    public function up()
    {
        $this->table('acl_roles')
                ->addColumn('name', 'string', ['null' => false])
                ->addColumn('description', 'text', ['null' => true])
                ->addColumn('removable', 'boolean', ['null' => false])
                ->create();
        
        $this->table('acl_resources')
                ->addColumn('name', 'string', ['null' => false])
                ->addColumn('description', 'text', ['null' => true])
                ->addColumn('scope', 'string', ['null' => true])
                ->create();
        
        $this->table('acl_resources_accesses')
                ->addColumn('acl_resource_id', 'integer', ['null' => false])
                ->addColumn('name', 'string', ['null' => false])
                ->addColumn('description', 'text', ['null' => true])
                ->addColumn('inherit', 'string', ['null' => true])
                ->create();
        
        $this->table('acl_access_list')
                ->addColumn('acl_role_id', 'integer', ['null' => false])
                ->addColumn('acl_resource_id', 'integer', ['null' => false])
                ->addColumn('acl_resource_access_id', 'integer', ['null' => false])
                ->addColumn('allowed', 'boolean', ['null' => false])
                ->create();
    }

    /**
     * Migrate Down.
     */
    public function down()
    {
        $this->table('acl_access_list')->drop();
        $this->table('acl_resources_accesses')->drop();
        $this->table('acl_resources')->drop();
        $this->table('acl_roles')->drop();
    }
}