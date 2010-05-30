
#include <scope/test.h>

#include "parser.h"
#include "dynamicFSM.h"
#include "utility.h"

#include <iostream>
#include <stack>
#include <boost/bind.hpp>

void parseOutput(std::string type, Node n) {
  std::cout << type << ": " << n.Val << std::endl;
}

SCOPE_TEST(parseAorB) {
  Parser     p;
  SyntaxTree tree;
  DynamicFSM& fsm(*p.getFsm());
  SCOPE_ASSERT(parse("a|b", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  SCOPE_ASSERT_EQUAL(3u, boost::num_vertices(fsm));
  SCOPE_ASSERT_EQUAL(2u, boost::out_degree(0, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(1, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(2, fsm));
}

SCOPE_TEST(parseAorBorC) {
  Parser     p;
  SyntaxTree tree;
  DynamicFSM& fsm(*p.getFsm());
  SCOPE_ASSERT(parse("a|b|c", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  SCOPE_ASSERT_EQUAL(4u, boost::num_vertices(fsm));
  SCOPE_ASSERT_EQUAL(3u, boost::out_degree(0, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(1, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(2, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(3, fsm));
}

SCOPE_TEST(parseAB) {
  Parser     p;
  SyntaxTree tree;
  DynamicFSM& fsm(*p.getFsm());
  SCOPE_ASSERT(parse("ab", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  SCOPE_ASSERT_EQUAL(3u, boost::num_vertices(fsm));
  SCOPE_ASSERT_EQUAL(1u, boost::out_degree(0, fsm));
  SCOPE_ASSERT_EQUAL(1u, boost::out_degree(1, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(2, fsm));
}

SCOPE_TEST(parseAlternationAndConcatenation) {
  Parser      p;
  SyntaxTree  tree;
  DynamicFSM& fsm(*p.getFsm());
  SCOPE_ASSERT(parse("a|bc", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  SCOPE_ASSERT_EQUAL(4u, boost::num_vertices(fsm));
  SCOPE_ASSERT_EQUAL(2u, boost::out_degree(0, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(1, fsm));
  SCOPE_ASSERT_EQUAL(1u, boost::out_degree(2, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(3, fsm));
}

SCOPE_TEST(parseGroup) {
  Parser      p;
  SyntaxTree  tree;
  DynamicFSM& fsm(*p.getFsm());
  SCOPE_ASSERT(parse("a(b|c)", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  SCOPE_ASSERT_EQUAL(4u, boost::num_vertices(fsm));
  SCOPE_ASSERT_EQUAL(1u, boost::out_degree(0, fsm));
  SCOPE_ASSERT_EQUAL(2u, boost::out_degree(1, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(2, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(3, fsm));
}

SCOPE_TEST(parseQuestionMark) {
  Parser      p;
  SyntaxTree  tree;
  // SCOPE_ASSERT(parse("a?", tree, boost::bind(&parseOutput, _1, _2)));
  // tree.Store.clear();
  // SCOPE_ASSERT(parse("a?", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  // SCOPE_ASSERT(!p.good());
  // tree.Store.clear();
  SCOPE_ASSERT(parse("ab?", tree, boost::bind(&Parser::callback, &p, _1, _2)));
  DynamicFSM& fsm(*p.getFsm());

  // both s1 and s2 should be match states... it appears that there's an edge duplication???
  // writeGraphviz(std::cerr, fsm);

  SCOPE_ASSERT_EQUAL(3u, boost::num_vertices(fsm));
  // get really invasive with testing here
  SCOPE_ASSERT_EQUAL(1u, boost::out_degree(0, fsm));
  SCOPE_ASSERT_EQUAL(1u, boost::out_degree(1, fsm));
  SCOPE_ASSERT_EQUAL(0u, boost::out_degree(2, fsm));
}
