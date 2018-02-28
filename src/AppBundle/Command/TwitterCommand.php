<?php

namespace AppBundle\Command;


use AppBundle\Services\TwitterFunctions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class TwitterCommand extends Command
{
    private $twitterFunctions;

    public function __construct($name = null, TwitterFunctions $twitterFunctions)
    {
        $this->twitterFunctions = $twitterFunctions;

        parent::__construct($name);
    }

    public function configure()
    {
        $this
            ->setName('app:auto-post-tweet');
    }

    public function execute(InputInterface $input, OutputInterface $output)
    {
        $output->writeln([
            'Auto post on Twitter',
            '=====================',
            '',
        ]);

        $twitter = $this->twitterFunctions->autoPostOnTwitter();

        if(isset($twitter))
        {
            $output->writeln("Your message has been posted on Twitter!");
        }else{
            $output->writeln("It seems there's an issue, please try again later!");
        }
    }

}