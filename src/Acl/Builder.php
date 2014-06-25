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
 
namespace Vegas\Security\Acl;

use Phalcon\Annotations\Adapter\Memory;
use Phalcon\Annotations\AdapterInterface;
use Phalcon\DI\InjectionAwareInterface;

/**
 * ACL resources builder
 * Class browses the list of modules provided in constructor and looks for controllers
 * For each controller annotations are parsed for extracting list of accesses
 *
 * Example usage:
 * <code>
 * namespace Test\Frontend;
 * /**
 *  *
 *  * @ACL(name='mvc:test:Frontend\Example', description='Example controller in Test module')
 *  *\/
 * class ExampleController {
 *
 *      /**
 *       *
 *       * @ACL(name='add', description='Add something')
 *       *\/
 *      public function addAction() {...}
 *
 *      /**
 *       *
 *       * @ACL(name='edit', description='Edit something')
 *       *\/
 *      public function editAction() {...}
 *
 *      /**
 *       *
 *       * @ACL(name='delete', description='Delete something')
 *       *\/
 *      public function deleteAction() {...}
 *
 *      /**
 *       *
 *       * @ACL(name='deleteAll', inherit='delete')
 *       *\/
 *      public function deleteAllAction() {...}
 * }
 * ...
 * $modules = array(
 *      'Test'  =>  array(
 *          'className' =>  'Test\Module',
 *          'path'  =>  APP_ROOT . '/app/module/Test/Module.php'
 *      )
 * );
 * $aclBuilder = new \Vegas\Security\Acl\Builder($modules);
 * $aclResources = $aclBuilder->build();
 * </code>
 *
 * In above example we create an Example controller belongs to Test module.
 * This controller has four public actions: add, edit, delete, deleteAll
 * The 'deleteAll' action inherits the 'delete' action, so in case
 * the access 'delete' is forbidden, action 'deleteAll' will be forbidden as well.
 * For action which does not inherit permission we can set a description, which
 * might be useful in the ACL manager in the frontend.
 * The argument 'name' is required.
 *
 * *** WARNING ***
 * ACL Builder is tight coupled with Vegas application structure!
 * /app
 *    /module
 *       /Test
 *          /controllers
 *             /frontend
 *                 ExampleController
 *             /backend
 *                 ExampleController
 *
 * @package Vegas\Security\Acl
 */
class Builder
{

    /**
     * List of application modules
     *
     * @var array
     */
    protected $modules;

    /**
     * List of ACL pre-defined resources from modules config
     *
     * @var array
     */
    protected $predefinedResources;

    /**
     * @var AdapterInterface
     */
    protected $annotationReader;

    /**
     * Setups modules and annotations reader
     *
     * @param array $modules
     * @param array $predefinedResources
     */
    public function __construct($modules, $predefinedResources = array())
    {
        $this->modules = $modules;
        $this->predefinedResources = $predefinedResources;
        $this->setupAnnotationsReader();
    }

    /**
     * Sets default annotations adapter
     * As default reader we use Memory
     */
    public function setupAnnotationsReader(AdapterInterface $adapter = null)
    {
        if (null == $adapter) {
            $this->annotationReader = new Memory();
        } else {
            $this->annotationReader = $adapter;
        }
    }

    /**
     * Relative directories paths, where controllers files are looked for
     *
     * @var array
     */
    protected $controllersDirectories = array(
        '/controllers/backend/', '/controllers/frontend/'
    );

    /**
     * Builds ACL resources from provided modules
     *
     * @throws \RuntimeException When controller file does not exist
     */
    public function build()
    {
        $aclResources = array();

        //browse modules
        foreach ($this->modules as $module) {
            $namespace = $this->getControllerNamespace($module);
            //browse controllers directories
            foreach ($this->controllersDirectories as $directory) {
                $controllers = $this->lookupControllers(dirname($module['path']) . $directory);
                //browse module controllers list
                foreach ($controllers as $controllerFile) {
                    $this->loadFile($controllerFile);
                    $controllerClassName = $this->getClassName($namespace, $controllerFile);
                    $annotations = $this->extractAnnotations($controllerClassName);
                    $aclResource = $this->parseAnnotations($annotations);

                    if (empty($aclResource)) continue;

                    $controllerScopeName = $this->getScopeName($controllerFile);//todo rewrite!
                    $aclResource['scope'] = $controllerScopeName;

                    $aclResources[] = $aclResource;
                }
            }
        }

        $aclResources = array_merge($aclResources, $this->parsePredefinedResources());

        return $aclResources;
    }

    /**
     * Returns the annotations reader
     *
     * @return Memory
     */
    protected function getAnnotationsReader()
    {
        if (!$this->annotationReader) {
            $this->setupAnnotationsReader();
        }
        return $this->annotationReader;
    }

    /**
     * Prepares list of controllers within indicated path
     *
     * @param $path
     * @return array
     */
    protected function lookupControllers($path)
    {
        $controllers = array();
        $controllerNamePattern = '*Controller.php';
        if (file_exists($path)) {
            foreach (glob($path . $controllerNamePattern) as $controllerFile) {
                $controllers[] = $controllerFile;
            }
        }

        return $controllers;
    }

    /**
     * Creates namespace for controller class
     * Each module has a path to Module.php file, containing configuration
     * We need a namespace for controllers from module
     *
     * @param $module
     * @return string
     */
    protected function getControllerNamespace($module)
    {
        $namespace = str_replace('Module', 'Controllers', $module['className']);
        return $namespace . '\\';
    }

    /**
     * Creates controller class name from indicated namespace and file path
     *
     * @param $namespace
     * @param $controllerFile
     * @return string
     */
    protected function getClassName($namespace, $controllerFile)
    {
        $scope = $this->getScopeName($controllerFile);
        $controllerName = pathinfo($controllerFile, PATHINFO_FILENAME);
        $className = sprintf("%s%s\\%s", $namespace, $scope, $controllerName);

        return $className;
    }

    /**
     * Extracts scope name from path to controller
     *
     * @param $controllerFile
     * @return mixed
     */
    protected function getScopeName($controllerFile)
    {
        $scope = pathinfo(dirname($controllerFile), PATHINFO_BASENAME);
        return $scope;
    }

    /**
     * File loader
     *
     * @param $filePath
     * @throws \RuntimeException
     */
    protected function loadFile($filePath)
    {
        if (file_exists($filePath) && is_readable($filePath)) {
            require_once $filePath;
        } else {
            throw new \RuntimeException(sprintf("Unable to load %s file", $filePath));
        }
    }

    /**
     * Extract all class annotations
     * The result contains annotations of class itself, class methods, class properties
     *
     * @param $className
     * @return array
     */
    protected function extractAnnotations($className)
    {
        $reader = $this->getAnnotationsReader();
        $reflector = $reader->get($className);
        $classAnnotations = $reflector->getClassAnnotations();
        $methodsAnnotations = $reflector->getMethodsAnnotations();
        $propertiesAnnotations = $reflector->getPropertiesAnnotations();

        return array(
            'class' => $classAnnotations,
            'methods' => $methodsAnnotations,
            'properties' => $propertiesAnnotations
        );
    }

    /**
     * Parses pre-defined resources from modules configs.
     *
     * @return array
     */
    protected function parsePredefinedResources()
    {
        $aclResources = array();
        foreach ($this->predefinedResources as $resourceName => $resource) {
            $aclResource = array();
            $aclResource['name'] = $resourceName;
            $aclResource['description'] = $resource['description'];
            $aclResource['accessList'] = $resource['accessList'];

            $aclResources[] = $aclResource;
        }

        return $aclResources;
    }

    /**
     * Parses annotations for extract acl resources
     *
     * @param $annotations
     * @internal param $scopeName
     * @return array
     */
    protected function parseAnnotations($annotations)
    {
        if (!$annotations['class'] instanceof \Phalcon\Annotations\Collection) {
            return array();
        }
        //get resource name from class annotation
        if (!$annotations['class']->has('ACL')) {
            return array();
        }
        $classAclAnnotation = $annotations['class']->get('ACL');
        $resource = $classAclAnnotation->getArguments();

        //get resource accesses from methods annotation
        $resource['accessList'] = array();

        $inheritedAccesses = array();
        foreach ($annotations['methods'] as $annotation) {
            if ($annotation->has('ACL')) {
                $methodAclAnnotation = $annotation->get('ACL');
                $args = $methodAclAnnotation->getArguments();
                if (isset($args['inherit'])) {
                    //create list of inherited access
                    $access = $args['inherit'];
                    if (!isset($inheritedAccesses[$access])) {
                        $inheritedAccesses[$access] = array();
                    }
                    $inheritedAccesses[$access][] = $args['name'];
                } else {
                    $args['inherit'] = '';
                    $resource['accessList'][$args['name']] = $args;
                }
            }
        }
        $this->resolveInheritedAccesses($resource['accessList'], $inheritedAccesses);

        return $resource;
    }

    /**
     * Resolves the inherited accesses
     * It is useful for accesses which inherits permission from another
     *
     * @param $resource
     * @param $inheritedAccesses
     */
    private function resolveInheritedAccesses(& $resource, $inheritedAccesses)
    {
        foreach ($inheritedAccesses as $parentAccess => $inheritedAccess) {
            foreach ($inheritedAccess as $access) {
                if (isset($resource[$parentAccess])) {
                    $resource[$parentAccess]['inherit'][] = $access;
                }
            }
        }
    }
}
