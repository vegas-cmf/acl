<?php

use Phinx\Migration\AbstractMigration;

class AddAclFieldIndexes extends AbstractMigration
{
    /**
     * Migrate Up.
     */
    public function up()
    {
        $this->table('acl_access_list')
                ->addForeignKey('acl_role_id', 'acl_roles', 'id', ['delete' => 'CASCADE', 'update' => 'NO_ACTION'])
                ->addForeignKey('acl_resource_id', 'acl_resources', 'id', ['delete' => 'CASCADE', 'update' => 'NO_ACTION'])
                ->addForeignKey('acl_resource_access_id', 'acl_resources_accesses', 'id', ['delete' => 'CASCADE', 'update' => 'NO_ACTION'])
                ->addIndex('allowed')
                ->save();
        
        $this->table('acl_resources_accesses')
                ->addForeignKey('acl_resource_id', 'acl_resources', 'id', ['delete' => 'CASCADE', 'update' => 'NO_ACTION'])
                ->addIndex('name')
                ->save();
        
        $this->table('acl_resources')
                ->addIndex('name')
                ->addIndex('scope')
                ->addIndex(['name', 'scope'], ['unique' => true])
                ->save();
        
        $this->table('acl_roles')
                ->addIndex('name', ['unique' => true])
                ->save();
    }

    /**
     * Migrate Down.
     */
    public function down()
    {
        $this->table('acl_access_list')
                ->dropForeignKey('acl_role_id')
                ->dropForeignKey('acl_resource_id')
                ->dropForeignKey('acl_resource_access_id')
                ->removeIndex('allowed')
                ->save();
        
        $this->table('acl_resources_accesses')
                ->dropForeignKey('acl_resource_id')
                ->removeIndex('name')
                ->save();
        
        $this->table('acl_resources')
                ->removeIndex('name')
                ->removeIndex('scope')
                ->removeIndex(['name', 'scope'], ['unique' => true])
                ->save();
        
        $this->table('acl_roles')
                ->removeIndex('name', ['unique' => true])
                ->save();
    }
}