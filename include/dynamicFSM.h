#pragma once

#include <boost/graph/adjacency_list.hpp>
#include "transition.h"

typedef boost::shared_ptr<Transition> TransitionPtr;

typedef boost::adjacency_list<boost::listS, boost::vecS, boost::directedS, boost::no_property, TransitionPtr> DynamicFSM;

typedef DynamicFSM::edge_descriptor EdgeIdx;